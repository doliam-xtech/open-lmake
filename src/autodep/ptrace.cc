// This file is part of the open-lmake distribution (git@github.com:doliam-xtech/open-lmake.git)
// Copyright (c) 2023-2026 Doliam
// This program is free software: you can redistribute/modify under the terms of the GPL-v3 (https://www.gnu.org/licenses/gpl-3.0.html).
// This program is distributed WITHOUT ANY WARRANTY, without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

#include "ebpf_event.h" // for magic related stuff

#include <err.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <linux/ptrace.h> // for struct ptrace_syscall_info, must be after sys/ptrace.h to avoid stupid request macro definitions

#include "disk.hh"
#include "non_portable.hh"
#include "process.hh"
#include "trace.hh"

#include "syscall_tab.hh"
#include "record.hh"

#include "ptrace.hh"

#if MUST_UNDEF_PTRACE_MACROS       // must be after utils.hh include
	#undef PTRACE_CONT             // /!\ stupid linux/ptrace.h defines ptrace requests as macros while ptrace expects an enum on some systems
	#undef PTRACE_GET_SYSCALL_INFO // .
	#undef PTRACE_PEEKDATA         // .
	#undef PTRACE_POKEDATA         // .
	#undef PTRACE_SETOPTIONS       // .
	#undef PTRACE_SYSCALL          // .
	#undef PTRACE_TRACEME          // .
#endif

using namespace Disk ;

// /!\ this function must be malloc free
static void _print_err(const char* reason) {
	const char* msg = ::strerror(errno) ;
	{ int rc = ::write( 2 , reason                   , ::strlen(reason                   ) ) ; (void)rc ; }
	{ int rc = ::write( 2 , " ("                     , ::strlen(" ("                     ) ) ; (void)rc ; }
	{ int rc = ::write( 2 , msg                      , ::strlen(msg                      ) ) ; (void)rc ; }
	{ int rc = ::write( 2 , ") when launching job\n" , ::strlen(") when launching job\n" ) ) ; (void)rc ; }
}

// runs in the child, just before execve /!\ this function must be malloc free as malloc takes a lock that may be held by another thread at the time process is cloned
int/*rc*/ AutodepPtrace::s_prepare_child(void*) {
	SyscallDescr::BpfProg const& bp = SyscallDescr::s_bpf_prog_ptrace ;
	// /!\ despite man page saying nothing, missing args must be 0 for prctl
	if (::ptrace(PTRACE_TRACEME,0/*pid*/,0/*addr*/,0/*data*/                          )!=0) { _print_err("cannot set up ptrace"     ) ; return 1 ; }
	if (::prctl (PR_SET_NO_NEW_PRIVS,1                  ,0/*arg3*/,0/*arg4*/,0/*arg5*/)!=0) { _print_err("cannot prevent privileges") ; return 1 ; }
	if (::prctl (PR_SET_SECCOMP     ,SECCOMP_MODE_FILTER,&bp      ,0/*.   */,0/*.   */)!=0) { _print_err("cannot set up seccomp"    ) ; return 1 ; }
	::raise(SIGSTOP) ;                                                                                                                               // wait until released by supervisor
	return 0 ;
}

namespace {

	struct TidInfo {
		static constexpr Bool3 Is32Dflt = HAS_32 ? Maybe : sizeof(void*)==8 ? No : Yes ;
		// cxtors & co
		TidInfo() = default ;
		TidInfo(pid_t tid) : record{New,tid} {}
		void operator>>(::string& os) const { os << proc_mem ; } // NO_COV
		// services
		void event( pid_t , int wstatus ) ;
	private :
		bool _do_magic_symlinkat( const uint64_t args[6] ) { //!                                                                     done
			int          dfd    = int  (args[1])                                             ; if (dfd!=EBPF_MAGIC_FD       ) return false ;
			off_t        target = off_t(args[0])                                             ;
			EbpfMagicReq req    ;
			ssize_t      cnt    = ::pread( proc_mem , &req , sizeof(EbpfMagicReq) , target ) ; if (cnt!=sizeof(EbpfMagicReq)) return false ;
			/**/                                                                               if (req.magic!=EBPF_MAGIC_VAL) return false ;
			switch (req.proc) { //!                                                      done
				case EBPF_MAGIC_DISABLE : SWEAR(!_disabled) ; _disabled = true  ; return true ;
				case EBPF_MAGIC_ENABLE  : SWEAR( _disabled) ; _disabled = false ; return true ;
			DN}
			return false/*done*/ ;
		}
		// data
	public :
		Record record   ;
		AcFd   proc_mem ;
		void*  ctx      = nullptr  ;
		long   syscall  = 0        ;
		Bool3  is_32    = Is32Dflt ;
	private :
		bool _disabled = false ;
	} ;

	void TidInfo::event( pid_t tid , int wstatus ) {
		static bool ctx_force_inval = false ;                                                                 // unused, just a marker for ctx
		static bool ctx_force_nosys = false ;                                                                 // .
		//
		int sig_in  = WSTOPSIG(wstatus) ;
		int sig_out = 0                 ;
		int event   = wstatus>>16       ;
		if (sig_in!=(SIGTRAP|0x80))
			switch (event) {
				case PTRACE_EVENT_SECCOMP : SWEAR_PROD(!ctx) ;                             break            ; // syscall enter
				case 0                    : if        (sig_in!=SIGTRAP) sig_out = sig_in ; goto NextSyscall ; // other stop reasons, wash SIGTRAP, ignore
				default                   : SWEAR_PROD(sig_in==SIGTRAP,sig_in) ;           goto NextSyscall ; // ignore other events
			}
		try {
			#if HAS_PTRACE_GET_SYSCALL_INFO                                                                   // use portable calls if implemented
				struct ::ptrace_syscall_info syscall_info ;
				if ( ::ptrace( PTRACE_GET_SYSCALL_INFO , tid , sizeof(struct ptrace_syscall_info) , &syscall_info )<=0 )
					throw cat("cannot get syscall info (",StrErr(),") from ",tid) ;
			#endif
			if (!ctx) {
				// syscall enter
				#if HAS_PTRACE_GET_SYSCALL_INFO
					SWEAR_PROD( syscall_info.op==PTRACE_SYSCALL_INFO_SECCOMP , syscall_info.op ) ;
					if (is_32==Maybe) is_32   = No|(NonPortable::is_32_from_audit_arch(syscall_info.arch)) ;
					/**/              syscall = syscall_info.seccomp.nr                                    ;
				#else
					if (is_32==Maybe) is_32   = No|NonPortable::ptrace_is_32(tid) ;
					/**/              syscall = NonPortable::ptrace_get_nr(tid)   ;                           // use non-portable calls if portable accesses are not implemented
				#endif
				#if !HAS_32
					if (is_32==Yes) {
						record.report_panic(
							cat("32-bit process ",read_lnk(cat("/proc/",tid,"/exe"))," (",tid,") on 64-bit host with no 32-bit support")
						,	false/*die*/
						) ;
						throw cat("bad arch 32-bit versus 64-bit") ;
					}
				#endif
				#ifdef __X32_SYSCALL_BIT
					syscall &= ~__X32_SYSCALL_BIT ;                                                           // we only look at char* args, so mode x32 has no impact
				#endif
				if ( syscall<0 || syscall>=SyscallDescr::NSyscalls ) {
					#if HAS_SECCOMP
						FAIL(is_32,syscall) ;                                                                 // bad syscalls should have been filtered out by BPF
					#else
						goto NextSyscall ;
					#endif
				}
				#if HAS_32
					SyscallDescr const& descr = is_32==Yes ? SyscallDescr::s_tab32[syscall] : SyscallDescr::s_tab[syscall] ;
				#else
					SyscallDescr const& descr =                                               SyscallDescr::s_tab[syscall] ;
				#endif
				if (!descr.entry) {
					#if HAS_SECCOMP
						FAIL(is_32,syscall) ;                                                                 // unhandled syscalls should have been filtered out by BPF
					#else
						goto NextSyscall ;
					#endif
				}
				#if HAS_PTRACE_GET_SYSCALL_INFO                                                               // use portable calls if implemented
					// ensure args is actually an array of uint64_t although one is declared as unsigned long and the other is unsigned long long
					auto& sc_args = syscall_info.seccomp.args ;
					static_assert( sizeof(sc_args[0])==sizeof(uint64_t) && ::is_unsigned_v<::remove_reference_t<decltype(sc_args[0])>> ) ;
					uint64_t* args = reinterpret_cast<uint64_t*>(sc_args) ;
				#else
					::array<uint64_t,6> arg_array = NonPortable::ptrace_get_args(tid) ;                       // use non-portable calls if portable accesses are not implemented
					uint64_t*           args      = arg_array.data()                  ;                       // we need a variable to hold the data while we pass the pointer
				#endif
				if (!proc_mem) proc_mem = AcFd( cat("/proc/",tid,"/mem") , {O_RDWR} ) ;
				//
				if ( syscall==SYS_symlinkat && _do_magic_symlinkat(args) ) goto NextSyscall ;                 // manage disabled tids before filtering them
				if ( _disabled                                           ) goto NextSyscall ;
				//
				bool refresh = false ;
				try { //!              vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
					tie(ctx,refresh) = descr.entry( record , proc_mem , args , false/*emulate*/ , descr.comment ) ;
					//                 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
					if (!descr.exit) SWEAR_PROD( !ctx , syscall ) ;                                           // no need for a context if we are not called at exit
				} catch(::string const& msg) {
					if (+msg) ctx = &ctx_force_inval ;
					else      ctx = &ctx_force_nosys ;
					NonPortable::ptrace_set_nr( tid , -1/*illegal syscall*/ ) ;                               // prevent execution of asked syscall
				}
				if (refresh) {
					proc_mem.close() ;
					is_32 = Is32Dflt ;
				}
			} else {
				// syscall exit
				int64_t       orig_rc = 0 ;
				int64_t/*rc*/ rc      ;
				if      (ctx==&ctx_force_inval) rc = -EINVAL ;
				else if (ctx==&ctx_force_nosys) rc = -ENOSYS ;
				else {
					#if HAS_PTRACE_GET_SYSCALL_INFO
						SWEAR_PROD( syscall_info.op==PTRACE_SYSCALL_INFO_EXIT ) ;
						orig_rc = syscall_info.exit.rval ;
					#else
						orig_rc = NonPortable::ptrace_get_res(tid) ;                                          // use non-portable calls if portable accesses are not implemented
					#endif
					#if HAS_32
						SyscallDescr const& descr = is_32==Yes ? SyscallDescr::s_tab32[syscall] : SyscallDescr::s_tab[syscall] ;
					#else
						SyscallDescr const& descr =                                               SyscallDescr::s_tab[syscall] ;
					#endif
					if (orig_rc<0) { rc = -1      ; errno = -orig_rc ; }
					else             rc = orig_rc ;
					SWEAR_PROD( descr.exit , is_32,syscall ) ;
					//   vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
					rc = descr.exit( ctx , record , proc_mem , rc ) ;
					//   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
					if (rc==-1) rc = -errno ;
				}
				if (rc!=orig_rc) NonPortable::ptrace_set_res( tid , rc ) ;
				ctx = nullptr ;
			}
		} catch (::string const& e) {
			Trace("event","process_is_dead",e) ;
		}
	NextSyscall :
		long rc = ::ptrace( ctx?PTRACE_SYSCALL:PTRACE_CONT , tid , 0/*addr*/ , sig_out ) ;
		throw_unless( rc==0||errno==ESRCH , "cannot continue (",StrErr(),") process ",tid ) ;
	}

}

int/*wstatus*/ AutodepPtrace::process(pid_t child_pid) {
	static constexpr int Options =
		PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK
	|	PTRACE_O_TRACESYSGOOD                                              // necessary to have a correct syscall_info.op field
	|	PTRACE_O_TRACESECCOMP
	|	PTRACE_O_EXITKILL                                                  // ensure no process is left stopped, even if alive at end of job
	;
	Trace trace("AutodepPtrace::process",child_pid) ;
	//
	Lock                  lock    { Record::s_mutex } ;                    // we have a single thread here, no need to lock record reporting, but Record code checks that lock is taken
	::umap<pid_t,TidInfo> tab     ;
	int                   wstatus ;
	pid_t                 tid     = ::wait(&wstatus)  ;                    // wait for child to stop
	SWEAR( tid==child_pid , tid,child_pid ) ;                              // job has not started yet, only a single child exists
	#if HAS_SECCOMP
		throw_unless( WIFSTOPPED(wstatus) , "cannot ptrace, consider using autodep='seccomp' instead" ) ;
	#else
		throw_unless( WIFSTOPPED(wstatus) , "cannot ptrace"                                         ) ;
	#endif
	{ long rc = ::ptrace(PTRACE_SETOPTIONS,tid,0/*addr*/,Options  ) ; swear_prod( rc==0 , cat("cannot set ptrace options (",StrErr(),") for process ",tid                        )) ; }
	{ long rc = ::ptrace(PTRACE_CONT      ,tid,0/*.   */,0/*data*/) ; swear_prod( rc==0 , cat("cannot continue ("          ,StrErr(),") process "    ,tid," after setting ptrace")) ; }
	//
	while( (tid=::wait(&wstatus))>1 ) {
		TidInfo& info = tab.try_emplace( tid , tid ).first->second ;
		if (WIFSTOPPED(wstatus)) {
			info.event(tid,wstatus) ;
		} else {
			SWEAR_PROD( WIFEXITED(wstatus) || WIFSIGNALED(wstatus) , "unrecognized wstatus ",wstatus," for tid ",tid ) ;
			tab.erase(tid) ;
			if (tid==child_pid) {
				trace("done",wstatus) ;
				return wstatus ;
			}
		}
	}
	fail_prod("process",child_pid,"cannot be waited for (",StrErr(),')') ; // NO_COV
}
