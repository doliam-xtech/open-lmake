// This file is part of the open-lmake distribution (git@github.com:doliam-xtech/open-lmake.git)
// Copyright (c) 2023-2026 Doliam
// This program is free software: you can redistribute/modify under the terms of the GPL-v3 (https://www.gnu.org/licenses/gpl-3.0.html).
// This program is distributed WITHOUT ANY WARRANTY, without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

// Root daemon for the ebpf autodep method.
// It loads and attaches the BPF programs ONCE (so every syscall on the machine traverses a single program set), then serves unprivileged job clients
// (job_exec/lautodep) over a unix socket : each client gets a private per-job ring buffer (fd passed via SCM_RIGHTS) into which the kernel routes that
// job's file-access events. The clients themselves never touch bpf() and need no privileges.
//
// The hooks used by the BPF programs are not all guaranteed interfaces (some may be inlined, renamed or have their signature changed from kernel to kernel).
// So, at start-up, the daemon runs a self-test : it traces a child that performs each kind of access and checks that the expected events are received.
// If not, it refuses to start (missing an access would silently lead to wrong builds).
//
// Each client is served by its own thread : registering and releasing a ring buffer in the kernel implies waiting for a rcu grace period (tens of ms),
// which must not be serialized among jobs.
//
// This is a standalone program (it deliberately avoids the lmake app framework) so as to be easily audited as it runs suid root.

#include <sys/syscall.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <fcntl.h>
#include <linux/io_uring.h>
#include <linux/openat2.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utime.h>

#include <cerrno>
#include <cstdarg>
#include <cstdlib>
#include <cstring>

#include <atomic>
#include <charconv>
#include <concepts>
#include <exception>
#include <filesystem>
#include <future>
#include <limits>
#include <set>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "sys_config.h"

#include "syscall_tab.h"

#include "ebpf_client.hh"
#include "ebpf_utils.hh"

#include "ebpf_event.h"
#include "src/autodep/ebpf.skel.h" // must follow ebpf_event.h, auto-generated, so must be located explicitly

static constexpr uint32_t RingBufSz = 4u<<20 ; // comfortable : events are small as paths are relative to roots and uninteresting accesses are filtered out in the kernel ...
/**/                                           // ... /!\ this memory is allocated in the kernel for each running job

using namespace std                  ;
using namespace std::string_literals ;
using namespace EbpfDaemon           ;

static constexpr uint32_t MaxExcludes  = 16 ; // max number of dirs a job can exclude, so a client cannot make the daemon hold an unbounded number of fds
static constexpr time_t   HelloTimeout = 10 ; // in seconds, a client must not be able to hold a thread without registering a job this memory is allocated in the kernel for each running job

static struct ebpf* _g_skel         = nullptr ;
static int          _g_ring_bufs_fd = -1      ;
static int          _g_root_tabs_fd = -1      ;

// use constexpr processing rather than                                          #ifdef/#endif so as to discriminate between defined/undefined macros on a single line
template<::integral I,I DfltVal> consteval I _macro_val_str(const char* n_str) {
	I    n      = 0     ;
	bool is_neg = false ;
	int  base   = 10    ;
	if (*n_str=='-') {
		if (!::is_signed_v<I>) return DfltVal ;
		is_neg = true ;
		n_str++ ;
	}
	if (*n_str=='0') {
		n_str++ ;
		if ( *n_str=='x' || *n_str=='X' ) { n_str++ ; base = 16 ; }
		else                                          base =  8 ;
	}
	for( const char* p=n_str ; *p ; p++ )
		if      ( '0'<=*p && *p<='9' && (*p-'0'   <base) ) { if (::is_same_v<I,bool>) n |= *p!='0' ; else n = (n*base) + (*p-'0'   ) ; }
		else if ( 'a'<=*p && *p<='z' && (*p-'a'+10<base) ) { if (::is_same_v<I,bool>) n  = true    ; else n = (n*base) + (*p-'a'+10) ; }
		else if ( 'A'<=*p && *p<='Z' && (*p-'A'+10<base) ) { if (::is_same_v<I,bool>) n  = true    ; else n = (n*base) + (*p-'A'+10) ; }
		else                                                 return DfltVal ;
	if ( !::is_same_v<I,bool> && is_neg ) n = -n ;
	return n ;
}
#define _MACRO_VAL_STR(x         ) #x                                                         // indirect macro to ensure we get the defined value when arg to MACRO_VAL is a defined macro
#define MACRO_VAL(     macro,dflt) _macro_val_str<decltype(dflt),dflt>(_MACRO_VAL_STR(macro))

// each running job needs a few fds (connection, ring buffer, dirs of interest), so the default limit would be reached with a few hundreds of jobs
static void _raise_limits() {
	struct rlimit old_rl = {} ;
	// open files
	rlim_t n_open_files = 100+_g_skel->rodata->NJobs*3 ; // 100 : overhead when loading ebpf filter, 3 : ring buf + root_tab + client socket ;
	if (::getrlimit(RLIMIT_NOFILE,&old_rl)!=0) {
		log_errno("cannot get max number of open files") ;
		return ;
	}
	if (old_rl.rlim_max<n_open_files) {
		n_open_files = old_rl.rlim_max ;
		log("reduced number of allowed open files from %u to %u",n_open_files,old_rl.rlim_max) ;
	}
	if (old_rl.rlim_cur<n_open_files) {
		struct rlimit new_rl = { .rlim_cur=n_open_files , .rlim_max=::max(old_rl.rlim_max,n_open_files) } ;
		if (::setrlimit(RLIMIT_NOFILE,&new_rl)!=0)
			log_errno("cannot raise the number of open files from %u to %u",old_rl.rlim_cur,n_open_files) ;
	}
	// memlock
	{	struct rlimit new_rl = { .rlim_cur=RLIM_INFINITY , .rlim_max=RLIM_INFINITY } ;
		if (::setrlimit(RLIMIT_MEMLOCK,&new_rl)!=0)
			log_errno("cannot raise memlock size") ;
	}
}
//
// syscalls
//

static constexpr struct ebpf const* EbpfTmpl  = nullptr                                                                        ;
static constexpr size_t             NSyscalls = sizeof(EbpfTmpl->rodata->Syscalls[0])/sizeof(EbpfTmpl->rodata->Syscalls[0][0]) ;

static constexpr bool SyscallsOk = []() {
	//
	bool ok = true ;
	// tracked syscalls
	#define X(   name , kind , d1,p1 , d2,p2 , mod,fl,msk,nf ) if ( long nr=MACRO_VAL(SYS_##name  ,-1L) ; nr>=0 ) ok &= ulong(nr)<NSyscalls ;
	#define X32( name , kind , d1,p1 , d2,p2 , mod,fl,msk,nf ) if ( long nr=MACRO_VAL(SYS32_##name,-1L) ; nr>=0 ) ok &= ulong(nr)<NSyscalls ;
	#define Y(   name                                        ) if ( long nr=MACRO_VAL(SYS_##name  ,-1L) ; nr>=0 ) ok &= ulong(nr)<NSyscalls ;
	#define Y32( name                                        ) if ( long nr=MACRO_VAL(SYS32_##name,-1L) ; nr>=0 ) ok &= ulong(nr)<NSyscalls ;
	EBPF_TRACKED_SYSCALLS  (X)
	EBPF_UNTRACKED_SYSCALLS(Y)
	#if HAS_32
		EBPF_TRACKED_SYSCALLS  (X32)
		EBPF_UNTRACKED_SYSCALLS(Y32)
	#endif
	#undef X
	#undef Y
	#undef X32
	#undef Y32
	return ok ;
} () ;
static_assert( SyscallsOk ) ;

static constexpr ::array<::array<EbpfScEntry,NSyscalls>,1+HAS_32> Syscalls = []() {
	::array<::array<EbpfScEntry,NSyscalls>,1+HAS_32> res ;
	// tracked syscalls
	#define X(  name,kind,d1,p1,d2,p2,mod,fl,msk,nf) if ( long nr=MACRO_VAL(SYS_##name  ,-1L) ; nr>=0 ) res[0][nr] = EBPF_SCE(kind,d1,p1,d2,p2,mod,fl,msk,nf) ;
	#define X32(name,kind,d1,p1,d2,p2,mod,fl,msk,nf) if ( long nr=MACRO_VAL(SYS32_##name,-1L) ; nr>=0 ) res[1][nr] = EBPF_SCE(kind,d1,p1,d2,p2,mod,fl,msk,nf) ;
	#define Y(  name                               ) if ( long nr=MACRO_VAL(SYS_##name  ,-1L) ; nr>=0 ) res[0][nr] = EBPF_SCE(NONE,-1,-1,-1,-1,-1 ,-1,-1 ,-1) ;
	#define Y32(name                               ) if ( long nr=MACRO_VAL(SYS32_##name,-1L) ; nr>=0 ) res[1][nr] = EBPF_SCE(NONE,-1,-1,-1,-1,-1 ,-1,-1 ,-1) ;
	EBPF_TRACKED_SYSCALLS  (X)
	EBPF_UNTRACKED_SYSCALLS(Y)
	#if HAS_32
		EBPF_TRACKED_SYSCALLS  (X32)
		EBPF_UNTRACKED_SYSCALLS(Y32)
	#endif
	#undef X
	#undef Y
	#undef X32
	#undef Y32
	return res ;
} () ;

//
// protocol
//

// the syscall table is shared by all jobs
static void _ebpf_init(struct ebpf* skel) {
	_raise_limits() ;
	// syscall table
	for( uint32_t is_32=0 ; is_32<1+HAS_32 ; is_32++ )
		for( uint32_t nr=0 ; nr<NSyscalls ; nr++ )
			skel->rodata->Syscalls[is_32][nr] = Syscalls[is_32][nr] ;
	// mrkr
	skel->rodata->Mrkr = g_mrkr ;
}

//
// main
//

// must be created while starting
struct Start {
	Start() {
		::string     lck_name  = get_file_name("lck")                                                      ;
		struct flock lck_start { .l_type=F_WRLCK , .l_whence=SEEK_SET , .l_start=0 , .l_len=1 , .l_pid=0 } ; // first byte is only held during startup
		struct flock lck_run   { .l_type=F_WRLCK , .l_whence=SEEK_SET , .l_start=1 , .l_len=1 , .l_pid=0 } ; // second byte is held during the entire daemon's life
		//
		_fd = ::open( lck_name.c_str() , O_RDWR|O_CREAT , 0600 ) ; if (_fd<0 ) throw "cannot open lock file : "s+strerror(errno) ;
		//
		// if another daemon is running, wait for the end of its start up sequence
		int rcs = ::fcntl( _fd , F_SETLKW , &lck_start ) ; if (rcs!=0) throw "cannot detect if another daemon is starting : "s+::strerror(errno) ;
		int rcr = ::fcntl( _fd , F_SETLK  , &lck_run   ) ;                                                                                         // stays acquired until end of process
		if (rcr!=0) {
			if ( errno==EAGAIN || errno==EACCES ) already_running = true ;
			else                                  throw "cannot detect if another daemon is running : "s+::strerror(errno) ;
		}
	}
	void started() {
		struct flock lck { .l_type=F_UNLCK , .l_whence=SEEK_SET , .l_start=0 , .l_len=1 , .l_pid=0 } ;                                             // first byte is only held during startup
		int          rc  = ::fcntl( _fd , F_SETLK  , &lck )                                          ; if (rc!=0) throw "cannot signal end of start-up : "s+::strerror(errno) ;
	}
	// data
	bool already_running = false ;
private :
	int _fd = -1 ;                                                                                                                                 // stays open until end of process
} ;

struct Job {
	static ::set<EbpfJobId> s_free_ids ;                                                                                                             // ordered to use as small job_ids as possible
	// cxtors & co
	Job() {
		if (s_free_ids.empty()) throw ::format("cannot allocate new idx") ;
		/**/     job_id    = *s_free_ids.begin() ; s_free_ids.erase(s_free_ids.begin()) ;
		uint32_t job_id_32 = job_id              ;
		//
		ring_buf_fd = ::bpf_map_create( BPF_MAP_TYPE_RINGBUF , nullptr/*map_name*/ , 0/*key_size*/ , 0/*value_size*/ , RingBufSz , nullptr/*opts*/ ) ;
		if (ring_buf_fd<0                                                                    ) throw ::format("job {} : cannot create ring buffer"  ,job_id) ;
		if (::bpf_map_update_elem( _g_ring_bufs_fd , &job_id_32 , &ring_buf_fd , BPF_ANY )!=0) throw ::format("job {} : cannot register ring buffer",job_id) ;
		//
		LIBBPF_OPTS( bpf_map_create_opts , opts , .map_flags=bpf_map__map_flags(_g_skel->maps.root_tab) ) ;
		root_tab_fd = ::bpf_map_create(
			BPF_MAP_TYPE_HASH
		,	nullptr/*map_name*/
		,	bpf_map__key_size   (_g_skel->maps.root_tab)
		,	bpf_map__value_size (_g_skel->maps.root_tab)
		,	bpf_map__max_entries(_g_skel->maps.root_tab)
		,	&opts
		) ;
		if (root_tab_fd<0                                                                    ) throw ::format("job {} : cannot create root table"  ,job_id) ;
		if (::bpf_map_update_elem( _g_root_tabs_fd , &job_id_32 , &root_tab_fd , BPF_ANY )!=0) throw ::format("job {} : cannot register root table",job_id) ;
	}
	~Job() {
		uint32_t job_id_32 = job_id ;
		if (::bpf_map_delete_elem( _g_ring_bufs_fd , &job_id_32 )!=0) log_errno(::format("job {} : cannot unregister ring buffer",job_id).c_str()) ; // cannot throw in dxtor
		if (::bpf_map_delete_elem( _g_root_tabs_fd , &job_id_32 )!=0) log_errno(::format("job {} : cannot unregister root table" ,job_id).c_str()) ; // .
		if (ring_buf_fd>=0                                          ) ::close(ring_buf_fd) ;
		if (root_tab_fd>=0                                          ) ::close(root_tab_fd) ;
		s_free_ids.insert(job_id) ;
	}
	// sevices
	void send_reply(int fd) {                                                                                // send the reply plus, on success, the ring buffer fd as an SCM_RIGHTS ancillary message
		struct iovec    iov                           = { .iov_base=&job_id , .iov_len=sizeof(EbpfJobId) } ;
		char            cbuf[CMSG_SPACE(sizeof(int))] = {}                                                 ;
		struct msghdr   msg                           = {
			.msg_name       = nullptr
		,	.msg_namelen    = 0
		,	.msg_iov        = &iov
		,	.msg_iovlen     = 1
		,	.msg_control    = cbuf
		,	.msg_controllen = sizeof(cbuf)
		,	.msg_flags      = 0
		} ;
		struct cmsghdr* cm = CMSG_FIRSTHDR(&msg) ;
		cm->cmsg_level = SOL_SOCKET            ;
		cm->cmsg_type  = SCM_RIGHTS            ;
		cm->cmsg_len   = CMSG_LEN(sizeof(int)) ;
		::memcpy( CMSG_DATA(cm) , &ring_buf_fd , sizeof(int) ) ;
		//
		int rc = ::sendmsg( fd , &msg , MSG_NOSIGNAL ) ; if (rc!=ssize_t(sizeof(EbpfJobId))) throw "cannot send reply"s ;
	}

	int       ring_buf_fd = -1 ;
	int       root_tab_fd = -1 ;
	EbpfJobId job_id      =  0 ;
} ;
::set<EbpfJobId> Job::s_free_ids ;

static int _pr( enum libbpf_print_level lvl , const char* fmt , va_list ap ) {
	if (lvl>LIBBPF_WARN)                                                       return 0 ;                                                             // higher lvl means less critical
	else                 { vlog(false/*with_errno*/,false/*with_nl*/,fmt,ap) ; return 1 ; }
}
static void _load_ebpf() {
	int rc ;
	/**/              ::libbpf_set_print(_pr                    ) ;
	_g_skel         = ebpf::open        (                       ) ; if (!_g_skel         ) throw "cannot open autodep ebpf filter"s                 ;
	/**/              _ebpf_init        (_g_skel                ) ;                                                                                   // init constant tables
	rc              = ebpf::load        (_g_skel                ) ; if (rc!=0            ) throw "cannot load autodep ebpf filter"s                 ;
	rc              = ebpf::attach      (_g_skel                ) ; if (rc!=0            ) throw "cannot attach autodep ebpf filter"s               ;
	_g_ring_bufs_fd = ::bpf_map__fd     (_g_skel->maps.ring_bufs) ; if (_g_ring_bufs_fd<0) throw "cannot open autodep ebpf filter ring buffer map"s ;
	_g_root_tabs_fd = ::bpf_map__fd     (_g_skel->maps.root_tabs) ; if (_g_root_tabs_fd<0) throw "cannot open autodep ebpf filter root table map"s  ;
	//
	if (_g_skel->rodata->NJobs  > 1<<(sizeof(EbpfJobId )*8) ) throw "too many job ids"       ;
	if (_g_skel->rodata->NRoots > 1<<(sizeof(EbpfRootId)*8) ) throw "too many roots per job" ;
	//
	for( size_t i=1 ; i<_g_skel->rodata->NJobs ; i++ ) Job::s_free_ids.insert(EbpfJobId(i)) ;                                                         // do not use 0 as it is reserved as sentinel
}

static const char* _g_exe = nullptr ;

[[noreturn]] static void _usage() {
	::fprintf( stderr , "usage : %s [lmake|test]\n" , _g_exe                                                                              ) ;
	::fprintf( stderr , "without argument            : runs forever as a daemon, useful to start it from systemctl\n"                     ) ;
	::fprintf( stderr , "with test as first argument : just run the auto-test and exit, useful for sanity check\n"                        ) ;
	::fprintf( stderr , "with lmake as first argument: it exits after a few minutes of inactivity, only useful for open-lmake internal\n" ) ;
	::exit(2) ;
}

void self_test() ;

int main( int argc , char* argv[] ) {
	_g_exe = argv[0] ;
	try {
		if (argc>2) _usage() ;
		::string arg     = argv[1] ;
		int      timeout ;
		if      (argc==1     ) timeout =      -1 ;
		if      (arg=="lmake") timeout = 300'000 ;                                                                                       // XXX? : auto calibrate by using 100*start_time
		else if (arg=="test" ) timeout =       0 ;
		else                   _usage() ;
		//
		::filesystem::create_directories(SockDir) ;
		Start start ;
		if (start.already_running) {
			log("daemon already running") ;
			::printf("0\n") ;                                                                                                            // report another daemon is up and running
			return 0 ;
		}
		reset_log() ;
		//
		_load_ebpf() ;
		//
		self_test() ;
		if (!timeout) return 0 ;
		//
		::string           master_name = get_sock_name()     ;
		const char*        master_cn   = master_name.c_str() ;
		struct sockaddr_un addr        = {}                  ; addr.sun_family = AF_UNIX ; ::strncpy( addr.sun_path , master_cn , sizeof(addr.sun_path)-1 ) ;
		//
		int master_fd = ::socket( AF_UNIX , SOCK_STREAM|SOCK_CLOEXEC , 0/*protocol*/ ) ; if (master_fd<0) { log_errno("cannot create socket") ; return 1 ; }
		//
		/**/::unlink( master_cn                                        )     ;                                                           // best effort
		if (::bind  ( master_fd , (struct sockaddr*)&addr,sizeof(addr) )!=0) { log_errno("cannot bind %s"     ,master_cn) ; return 1 ; }
		/**/::chmod ( master_cn , 0666                                 )     ;                                                           // best effort, allow unprivileged jobs
		if (::listen( master_fd , 64                                   )!=0) { log_errno("cannot listen on %s",master_cn) ; return 1 ; }
		log("ready, listening on %s",master_cn) ;
		start.started() ;
		::printf("1\n") ;                                                                                                                // report we are up and running
		::fclose(stdout) ;
		//
		::vector<::epoll_event>  events ;
		::unordered_map<int,Job> jobs   ;
		int                      ep_fd  = ::epoll_create1(EPOLL_CLOEXEC) ; if (ep_fd<0) throw "cannot create epoll fd"s ;
		//
		::epoll_event e { .events=EPOLLIN , .data{.fd=master_fd} } ;
		if (::epoll_ctl(ep_fd,EPOLL_CTL_ADD,master_fd,&e)!=0) throw "cannot add master event to epoll fd"s ;
		events.push_back({}) ;
		for( uint8_t n_wait_jobs=1 ;;) {                                                                                                 // wait for first job (that launched us)
			int to = timeout ;
			if (n_wait_jobs              ) to = -1 ;
			if (events.size()>1/*master*/) to = -1 ;                                                                                     // waiting for on going jobs
			int n_events = ::epoll_wait( ep_fd , events.data() , events.size() , to ) ; if ( n_events<0) throw "cannot wait epoll fd"s ;
			/**/                                                                        if (!n_events  ) break ;                         // timeout has expired
			//
			int events_sz = events.size() ;
			for( int i=0 ; i<n_events ; i++ ) {
				::epoll_event const& event = events[i] ;
				if (event.data.fd==master_fd) {
					int           job_fd      = ::accept4( master_fd , nullptr/*addr*/ , nullptr/*addrlen*/ , SOCK_CLOEXEC ) ;
					::pair        it_inserted = jobs.try_emplace(job_fd)                                                     ; if (!it_inserted.second) throw "cannot insert job in book-keeping"s ;
					Job&          job         = it_inserted.first->second                                                    ;
					::epoll_event e           { .events=EPOLLIN , .data{.fd=job_fd} }                                        ;
					if (::epoll_ctl( ep_fd , EPOLL_CTL_ADD , job_fd , &e )!=0) throw "cannot add new job to epoll"s ;
					job.send_reply(job_fd) ;
					events_sz++ ;
					if (n_wait_jobs) n_wait_jobs-- ;
				} else {
					auto it = jobs.find(event.data.fd) ; if (it==jobs.end()) throw "cannot retreive job in book-keeping"s ;
					if (::epoll_ctl( ep_fd , EPOLL_CTL_DEL , event.data.fd , nullptr )!=0) throw "cannot remove done job from epoll"s ;
					::close(event.data.fd) ;
					events_sz-- ;
					jobs.erase(it) ;
				}
			}
			events.resize(events_sz) ;
		}
	}
	catch (::string    const& e) { log("daemon : %s",e.c_str()) ; return 1 ; }
	catch (::exception const& e) { log("daemon : %s",e.what() ) ; return 1 ; }
	return 0 ;
}

//
// self test : check all hooks are activated in ebpf filter
//

struct Consumer {
	void handle_event( ThreadCtx const& , EbpfEventHdr const& hdr , Path const& ) {
		if      (hdr.kind< EBPF_HAS_DATA         ) {}
		else if (hdr.kind==EBPF_PANIC            ) n_panic++    ;
		else if (hdr.file_kind==EBPF_FILE_UNKNOWN) n_unsolved++ ;
		else                                       n_solved++   ;
	}
	// data
	int n_solved   = 0 ;
	int n_unsolved = 0 ;
	int n_panic    = 0 ;
} ;

struct IoUring {
	static constexpr long QueueSz = 16 ;
	template<class T> static T* s_map( size_t sz , int fd , off_t off ) {
		return static_cast<T*>(::mmap( nullptr , sz , PROT_READ|PROT_WRITE , MAP_SHARED|MAP_POPULATE , fd , off )) ;
	}
	// cxtors & co
	IoUring(bool activate) {
		if (!activate) return ;
		//
		::io_uring_params params = {} ;
		//
		params.flags          |= IORING_SETUP_SQPOLL                                                ;
		params.sq_thread_idle  = 0                                                                  ;
		ring_fd                = ::syscall( SYS_io_uring_setup , QueueSz , &params )                ; if (ring_fd<0         ) throw "cannot setup io_uring"s       ;
		sq_ring_sz             = params.sq_off.array + params.sq_entries*sizeof(uint32_t)           ;
		sqe_sz                 =                      params.sq_entries*sizeof(::io_uring_sqe)      ;
		sq_ptr                 = s_map<char          >( sq_ring_sz , ring_fd , IORING_OFF_SQ_RING ) ; if (sq_ptr==MAP_FAILED) throw "cannot map io_uring"s         ;
		sqes                   = s_map<::io_uring_sqe>( sqe_sz     , ring_fd , IORING_OFF_SQES    ) ; if (sqes  ==MAP_FAILED) throw "cannot map io_uring entries"s ;
		sq_tail                =  reinterpret_cast<uint    *>( sq_ptr + params.sq_off.tail      )   ;
		sq_array               =  reinterpret_cast<uint    *>( sq_ptr + params.sq_off.array     )   ;
		sq_flags               =  reinterpret_cast<uint32_t*>( sq_ptr + params.sq_off.flags     )   ;
		ring_mask              = *reinterpret_cast<uint    *>( sq_ptr + params.sq_off.ring_mask )   ;
	}
	~IoUring() {
		if (ring_fd>=0) {
			::munmap( sqes   , sqe_sz     ) ;
			::munmap( sq_ptr , sq_ring_sz ) ;
			::close ( ring_fd             ) ;
		}
	}
	// services
	void submit( uint8_t op , int fd1 , const char* addr1 , int opt1=-1 , const char* opt2=nullptr , uint32_t flags=-1 , const char* addr3=nullptr ) {
		uint            tail = *sq_tail  ; if ((tail&ring_mask)!=tail) throw "queue is too short"s ;
		::io_uring_sqe& sqe = sqes[tail] ; sqe = {} ;
		//
		/**/                     sqe.flags      = IOSQE_ASYNC|IOSQE_IO_LINK ; // ensure ordered execution
		/**/                     sqe.opcode     =       op                  ;
		/**/                     sqe.fd         =       fd1                 ;
		/**/                     sqe.addr       = ulong(addr1)              ;
		if (opt1 !=-1          ) sqe.len        =       opt1                ; // not all fields are necessary for all opcodes
		if (opt2 !=nullptr     ) sqe.addr2      = ulong(opt2 )              ; // .
		if (flags!=uint32_t(-1)) sqe.open_flags =       flags               ; // .
		if (addr3!=nullptr     ) sqe.addr3      = ulong(addr3)              ; // .
		//
		sq_array[tail] = tail ;
		__atomic_store_n( sq_tail , tail+1 , __ATOMIC_RELEASE ) ;
		n_reqs++ ;
	}
	void flush() {
		if (__atomic_load_n(sq_flags,__ATOMIC_ACQUIRE)&IORING_SQ_NEED_WAKEUP) ::syscall( SYS_io_uring_enter , ring_fd , 0 , 0 , IORING_ENTER_SQ_WAKEUP , nullptr , 0 ) ;
		int rc = ::syscall( SYS_io_uring_enter, ring_fd , 0 , n_reqs , IORING_ENTER_GETEVENTS , nullptr , 0 ) ; if (rc!=0) throw "cannot wait fo io_uring to complete"s ;
	}
	// data
	int             ring_fd    = -1      ;
	size_t          sq_ring_sz = 0       ;
	size_t          sqe_sz     = 0       ;
	char          * sq_ptr     = nullptr ;
	::io_uring_sqe* sqes       = nullptr ;
	uint          * sq_tail    = nullptr ;
	uint          * sq_array   = nullptr ;
	uint32_t      * sq_flags   = nullptr ;
	uint            ring_mask  = 0       ;
	uint            n_reqs     = 0       ;
} ;

// goal of self test is to ensure all ebpf hooks are actually attached
Consumer tracee(::string dir_name={}) {
	bool work = !dir_name.empty() ;
	//
	Consumer res ;
	//
	if (work) RingBufBase::s_start_job() ;
	//
	char*              sentinel = nullptr       ;
	::string           abs_d    = dir_name+"/d" ;
	const char*        abs_d_c  = abs_d.c_str() ;
	::string           abs_f    = dir_name+"/f" ;
	const char*        abs_f_c  = abs_f.c_str() ;
	::string           abs_g    = dir_name+"/g" ;
	const char*        abs_g_c  = abs_g.c_str() ;
	::string           abs_l    = dir_name+"/l" ;
	const char*        abs_l_c  = abs_l.c_str() ;
	int                mid      ;
	int                dfd      ;
	struct file_handle fh       ;
	struct open_how    how      {}              ; how.flags = O_RDONLY ;
	struct stat        st       ;
	struct statx       stx      ;
	struct statfs      stfs     ;
	struct utimbuf     utb      {}              ;
	struct timeval     tv[2]    {}              ;
	struct timespec    ts[2]    {}              ;
	char               v[]      = "value"       ;
	char               buf[100] ;
	//
	// This sequence leaks some fd's but we do not care as we are in an isolated process that will die shortly
	//
	if (work) dfd = ::open( dir_name.c_str() , O_DIRECTORY ) ; else res.n_solved += 1 ;
	//
	if (work) ::syscall( SYS_creat             ,       abs_f_c , 0666                                       ) ; else res.n_solved   += 1 ;
	if (work) ::syscall( SYS_access            ,       abs_f_c , X_OK                                       ) ; else res.n_solved   += 1 ;
	if (work) ::syscall( SYS_faccessat         ,       dfd,"f" , X_OK         , 0                           ) ; else res.n_solved   += 1 ;
	if (work) ::syscall( SYS_faccessat2        ,       dfd,"f" , X_OK         , 0                           ) ; else res.n_solved   += 1 ;
	if (work) ::syscall( SYS_chdir             ,       "."                                                  ) ; else res.n_solved   += 0 ;
	if (work) ::syscall( SYS_chmod             ,       abs_f_c , 0777                                       ) ; else res.n_solved   += 1 ;
	if (work) ::syscall( SYS_fchmodat          ,       dfd,"f" , 0777         , 0                           ) ; else res.n_solved   += 1 ;
	if (work) ::syscall( SYS_execve            ,       abs_f_c , &sentinel    , &sentinel                   ) ; else res.n_unsolved += 1 ;
	if (work) ::syscall( SYS_execveat          ,       dfd,"f" , &sentinel    , &sentinel                   ) ; else res.n_unsolved += 1 ;
	if (work) ::syscall( SYS_link              ,       abs_f_c , abs_g_c                                    ) ; else res.n_solved   += 2 ;
	if (work) ::syscall( SYS_unlink            ,       abs_g_c                                              ) ; else res.n_solved   += 1 ;
	if (work) ::syscall( SYS_linkat            ,       dfd,"f" , dfd,"g"      , 0                           ) ; else res.n_solved   += 2 ;
	if (work) ::syscall( SYS_unlinkat          ,       dfd,"g" , 0                                          ) ; else res.n_solved   += 1 ;
	if (work) ::syscall( SYS_mkdir             ,       abs_d_c , 0777                                       ) ; else res.n_solved   += 1 ;
	if (work) ::syscall( SYS_rmdir             ,       abs_d_c                                              ) ; else res.n_solved   += 1 ;
	if (work) ::syscall( SYS_mkdirat           ,       dfd,"d" , 0777                                       ) ; else res.n_solved   += 1 ;
	if (work) ::syscall( SYS_rmdir             ,       abs_d_c                                              ) ; else res.n_solved   += 1 ;
	if (work) ::syscall( SYS_mknod             ,       abs_g_c , S_IFREG|0666 , 0                           ) ; else res.n_solved   += 1 ;
	if (work) ::syscall( SYS_unlink            ,       abs_g_c                                              ) ; else res.n_solved   += 1 ;
	if (work) ::syscall( SYS_mknodat           ,       dfd,"g" , S_IFREG|0666 , 0                           ) ; else res.n_solved   += 1 ;
	if (work) ::syscall( SYS_unlinkat          ,       dfd,"g" , 0                                          ) ; else res.n_solved   += 1 ;
	if (work) ::syscall( SYS_name_to_handle_at ,       dfd,"f" , &fh          , &mid        , 0             ) ; else res.n_solved   += 1 ;
	if (work) ::syscall( SYS_open              ,       abs_f_c , O_RDONLY                                   ) ; else res.n_solved   += 1 ;
	if (work) ::syscall( SYS_openat            ,       dfd,"f" , O_RDONLY                                   ) ; else res.n_solved   += 1 ;
	if (work) ::syscall( SYS_openat2           ,       dfd,"f" , &how         , sizeof(how)                 ) ; else res.n_solved   += 1 ;
	if (work) ::syscall( SYS_symlink           , "f" , abs_l_c                                              ) ; else res.n_solved   += 1 ;
	if (work) ::syscall( SYS_unlink            ,       abs_l_c                                              ) ; else res.n_solved   += 1 ;
	if (work) ::syscall( SYS_symlinkat         , "g" , dfd,"l"                                              ) ; else res.n_solved   += 1 ;
	if (work) ::syscall( SYS_readlink          ,       abs_l_c , buf          , sizeof(buf)                 ) ; else res.n_solved   += 1 ;
	if (work) ::syscall( SYS_readlinkat        ,       dfd,"l" , buf          , sizeof(buf)                 ) ; else res.n_solved   += 1 ;
	if (work) ::syscall( SYS_rename            ,       abs_f_c , abs_g_c                                    ) ; else res.n_solved   += 2 ;
	if (work) ::syscall( SYS_renameat          ,       dfd,"g" , dfd,"f"                                    ) ; else res.n_solved   += 2 ;
	if (work) ::syscall( SYS_renameat2         ,       dfd,"f" , dfd,"g"      , 0                           ) ; else res.n_solved   += 2 ;
	if (work) ::syscall( SYS_stat              ,       abs_l_c , &st                                        ) ; else res.n_solved   += 2 ;
	if (work) ::syscall( SYS_lstat             ,       abs_l_c , &st          , 0                           ) ; else res.n_solved   += 1 ;
	if (work) ::syscall( SYS_statx             ,       dfd,"l" , 0            , 0           , &stx          ) ; else res.n_solved   += 2 ;
	if (work) ::syscall( SYS_newfstatat        ,       dfd,"l" , &st          , 0                           ) ; else res.n_solved   += 2 ;
	if (work) ::syscall( SYS_statfs            ,       abs_g_c , &stfs                                      ) ; else res.n_solved   += 1 ;
	if (work) ::syscall( SYS_truncate          ,       abs_g_c , 0                                          ) ; else res.n_solved   += 1 ;
	if (work) ::syscall( SYS_utime             ,       abs_g_c , &utb                                       ) ; else res.n_solved   += 1 ;
	if (work) ::syscall( SYS_utimes            ,       abs_g_c , tv                                         ) ; else res.n_solved   += 1 ;
	if (work) ::syscall( SYS_utimensat         ,       dfd,"g" , ts           , 0                           ) ; else res.n_solved   += 1 ;
	if (work) ::syscall( SYS_setxattr          ,       abs_g_c , "user.name"  , v           , sizeof(v) , 0 ) ; else res.n_solved   += 1 ;
	if (work) ::syscall( SYS_getxattr          ,       abs_g_c , "user.name"  , v           , sizeof(v)     ) ; else res.n_solved   += 1 ;
	if (work) ::syscall( SYS_listxattr         ,       abs_g_c , v            , sizeof(v)                   ) ; else res.n_solved   += 1 ;
	if (work) ::syscall( SYS_removexattr       ,       abs_g_c , "user.name"                                ) ; else res.n_solved   += 1 ;
	if (work) ::syscall( SYS_lsetxattr         ,       abs_l_c , "user.name"  , v           , sizeof(v) , 0 ) ; else res.n_solved   += 1 ;
	if (work) ::syscall( SYS_lgetxattr         ,       abs_l_c , "user.name"  , v           , sizeof(v)     ) ; else res.n_solved   += 1 ;
	if (work) ::syscall( SYS_llistxattr        ,       abs_l_c , v            , sizeof(v)                   ) ; else res.n_solved   += 1 ;
	if (work) ::syscall( SYS_lremovexattr      ,       abs_l_c , "user.name"                                ) ; else res.n_solved   += 1 ;
	if (work) ::syscall( SYS_unlink            ,       abs_l_c                                              ) ; else res.n_solved   += 1 ;
	//
	IoUring uring { work } ;
	//
	if (work) uring.submit( IORING_OP_OPENAT    , dfd      , "g"         , 0           , 0                             , O_RDONLY           ) ; else res.n_solved += 1 ;
	if (work) uring.submit( IORING_OP_OPENAT2   , dfd      , "g"         , sizeof(how) , reinterpret_cast<char*>(&how)                      ) ; else res.n_solved += 1 ;
	if (work) uring.submit( IORING_OP_MKDIRAT   , dfd      , "d"         , 0777                                                             ) ; else res.n_solved += 1 ;
	if (work) uring.submit( IORING_OP_STATX     , dfd      , "g"         , STATX_SIZE  , reinterpret_cast<char*>(&stx)                      ) ; else res.n_solved += 1 ;
	if (work) uring.submit( IORING_OP_SYMLINKAT , dfd      , "g"         , -1          , "l"                                                ) ; else res.n_solved += 1 ;
	if (work) uring.submit( IORING_OP_LINKAT    , dfd      , "g"         , dfd         , "g2"                                               ) ; else res.n_solved += 2 ;
	if (work) uring.submit( IORING_OP_RENAMEAT  , dfd      , "g2"        , dfd         , "g3"                                               ) ; else res.n_solved += 2 ;
	if (work) uring.submit( IORING_OP_UNLINKAT  , dfd      , "g3"                                                                           ) ; else res.n_solved += 1 ;
	// XXX : fix xattr in io_uring
//	if (work) uring.submit( IORING_OP_SETXATTR  , AT_FDCWD , "user.name" , sizeof(v)   , v                             , 0        , abs_g_c ) ; else res.n_solved += 1 ;
//	if (work) uring.submit( IORING_OP_GETXATTR  , AT_FDCWD , "user.name" , sizeof(v)   , v                             , -1       , abs_g_c ) ; else res.n_solved += 1 ;
	//
	if (work) uring.flush() ;
	if (work) ::close(dfd)  ;
	//
	return res ;
}

void self_test() {
	::string msg ;
	try {
		::string          dir_name = get_file_name("test_dir")      ;
		Job               job      ;
		RingBuf<Consumer> ring_buf { job.job_id , job.ring_buf_fd } ;
		//
		::filesystem::remove_all( dir_name                ) ;
		::mkdir                 ( dir_name.c_str() , 0777 ) ;
		RingBufBase::s_add_root( EBPF_ROOT_ID_PLAIN , dir_name ) ;
		//
		if ( pid_t child=fork() ; !child ) {            // in child
			tracee(dir_name) ;
			exit(0) ;
		} else {                                        // in parent
			if (child<0) throw "cannot spawn tracee"s ;
			//
			int           fd    = ::epoll_create1(EPOLL_CLOEXEC)                                 ;
			::epoll_event event { .events=EPOLLIN , .data={} }                                   ;
			int           rc    = ::epoll_ctl( fd , EPOLL_CTL_ADD , ring_buf.epoll_fd , &event ) ; if (rc!=0) throw "cannot epoll"s ;
			//
			for (;;) {
				::epoll_wait( fd , &event , 1/*maxevents*/ , -1/*timeout*/ ) ;
				if (ring_buf.consume()) break ;
			}
			::waitpid( child , nullptr/*wstatus*/ , 0/*options*/ ) ;
		}
		Consumer expected = tracee() ;
		if (ring_buf.consumer.n_panic   !=expected.n_panic   ) throw ::format( "bad panic  event count : expected {}, received {}"   , expected.n_panic   ,ring_buf.consumer.n_panic   ) ;
		if (ring_buf.consumer.n_solved  !=expected.n_solved  ) throw ::format( "bad solved event count : expected {}, received {}"   , expected.n_solved  ,ring_buf.consumer.n_solved  ) ;
		if (ring_buf.consumer.n_unsolved!=expected.n_unsolved) throw ::format( "bad unsolved event count : expected {}, received {}" , expected.n_unsolved,ring_buf.consumer.n_unsolved) ;
		//
	}
	catch (::string    const& e) { msg = e        ; }
	catch (::exception const& e) { msg = e.what() ; }
	if (!msg.empty()) {
		fprintf( stderr , "self-test broken : %s\n" , msg.c_str() ) ;
		exit(2) ;
	}
}
