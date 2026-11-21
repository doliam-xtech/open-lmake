// This file is part of the open-lmake distribution (git@github.com:doliam-xtech/open-lmake.git)
// Copyright (c) 2023-2026 Doliam
// This program is free software: you can redistribute/modify under the terms of the GPL-v3 (https://www.gnu.org/licenses/gpl-3.0.html).
// This program is distributed WITHOUT ANY WARRANTY, without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

#include "ebpf_event.h"

#include "disk.hh"
#include "re.hh"
#include "time.hh"
#include "version.hh"

#include "env.hh"
#include "record.hh"

#include "job_support.hh"

using namespace Disk ;
using namespace Hash ;
using namespace Re   ;
using namespace Time ;

using namespace Codec ;

using Proc = JobExecProc ;

namespace JobSupport {

	static void _chk_files(::vector_s const& files) {
		for( ::string const& f : files ) throw_unless( f.size()<=PATH_MAX , "filename too long (",f.size()," characters)" ) ;
	}

	static thread_local bool _t_disabled = false ;

	bool get_enable() {
		return !_t_disabled ;
	}

	void set_enable(bool en) {
		if (en==!_t_disabled) return ;
		EbpfMagicReq req ;
		/**/    req.magic = EBPF_MAGIC_VAL     ; // compulsery for req to be recognized
		if (en) req.proc  = EBPF_MAGIC_ENABLE  ;
		else    req.proc  = EBPF_MAGIC_DISABLE ;
		int rc = ::symlinkat( reinterpret_cast<const char*>(&req) , EBPF_MAGIC_FD , "" ) ; (void)rc ;
		_t_disabled = !en ;
	}

	struct AutodepSilent {
		AutodepSilent () : sav_en{get_enable()} { set_enable(false) ; }
		~AutodepSilent()                        { set_enable(true ) ; }
		bool sav_en ;
	} ;

	struct LockedRecord {
		// static data
		static Record* s_record ;
		// cxtors & co
		LockedRecord() {
			if (!s_record) s_record = new Record{New} ;
		}
		// accesses
		Record& operator* () { return *s_record ; }
		Record* operator->() { return &**this   ; }
		// data
		Lock<Mutex<MutexLvl::Record>> lock = {Record::s_mutex} ;
	} ;
	Record* LockedRecord::s_record = nullptr ;

	::pair<::vector<VerboseInfo>,bool/*ok*/> depend( ::vector_s&& files , AccessDigest ad , bool no_follow , bool regexpr , bool direct , bool verbose ) {
		bool         do_read = +(ad.accesses&FullAccesses) ;
		bool         sync    = direct || verbose           ;
		LockedRecord record  ;
		//
		throw_if( regexpr + verbose + direct > 1 , "regexpr, verbose and direct are mutually exclusive" ) ;
		if (regexpr) {
			SWEAR(ad.write==No) ;
			throw_if( !no_follow , "regexpr and follow_symlinks are exclusive" ) ;
			throw_if( do_read    , "regexpr and read are exclusive"            ) ;
		} else {
			ad.flags.extra_dflags |= ExtraDflag::NoStar ;                                                   // ignore regexpr based flags if specified specifically
		}
		if (ad.flags.extra_dflags[ExtraDflag::ReaddirOk]) {
			ad.flags.dflags &= ~Dflag::Required ;                                                           // ReaddirOk means dep is expected to be a dir, it is non-sens to require it to be buidlable
			ad.read_dir     |= +ad.accesses     ;                                                           // if reading and allow dir access, assume user meant reading a dir
		}
		if (verbose) {
			bool ignore_err = ad.flags.dflags[Dflag::IgnoreError] ;
			throw_unless( do_read || ignore_err , "verbose is meaningless without read or ignore_error" ) ;
			if (do_read   )   ad.force_is_dep  = true        ;                                              // we access the content of the file even if file has been written to
			if (ignore_err) { ad.accesses     |= Access::Err ; do_read = true ; }                           // if errors are not ignored, reporting them is meaningless as deps are necessarily ok
		}
		_chk_files(files) ;
		//
		if (regexpr) {
			::vmap_s<FileInfo> files_ ; for( ::string& f : files ) files_.emplace_back(::move(f),FileInfo()) ;
			record->report_sync( { .proc=JobExecProc::AccessPattern , .comment=Comment::Depend , .digest=ad , .date=New , .files=::move(files_) } ) ;
			 return {{},true/*ok*/} ;
		}
		::vector<NodeIdx> dep_idxs1 ; dep_idxs1.reserve(files.size()) ;
		JobExecRpcReq     jerr      {
			.sync    = No|sync
		,	.comment = Comment::Depend
		,	.digest  = ad
		,	.date    = New
		} ;
		{	AutodepSilent as ;                                                                              // dont report accesses made to establish what to report
			for( ::string& f : files ) {
				Record::Solve<false/*Send*/> sr { *record , f , no_follow , do_read , Comment::Depend } ;
				if ( ad.flags.extra_dflags[ExtraDflag::ReaddirOk] && sr.file_loc==FileLoc::RepoRoot ) {     // when passing flag readdir_ok, we may want to report top-level dir
					sr.file_loc = FileLoc::Repo ;
					sr.real     = "."s          ;                                                           // /!\ a (warning) bug in gcc-12 is triggered if using "." here instead of "."s
				}
				if (sr.file_loc>FileLoc::Dep) { dep_idxs1.push_back(0                  ) ; continue ; }     // 0 means no dep info
				else                            dep_idxs1.push_back(jerr.files.size()+1) ;                  // start at 1 as 0 is reserved to mean no dep info
				ad.accesses |= sr.accesses ;                                                                // seems pessimistic (as all accesses will apply to all files) ...
				if (sync) jerr.files.emplace_back(::move(sr.real),FileInfo(       )) ;                      // ... but sr.accesses does not actually depend on file, only on no_follow, read and write
				else      jerr.files.emplace_back(::move(sr.real),FileInfo(sr.real)) ;
			}
		}
		if (!sync) {
			jerr.proc= JobExecProc::Access ;
			if (+jerr.files) {
				record->report_access(::move(jerr)) ;
				record->send_report() ;
			}
			return { {} , true/*ok*/ } ;
		}
		if (verbose) {
			jerr.proc         = JobExecProc::DepVerbose ;
			jerr.comment_exts = CommentExt::Verbose     ;
			JobExecRpcReply       reply ; if (+jerr.files) reply = record->report_sync(::move(jerr)) ;
			::vector<VerboseInfo> res   ; res.reserve(files.size()) ;
			for( size_t i : iota(files.size()) )
				if (!dep_idxs1[i]) res.push_back({}                                         ) ;             // 0 is reserved to mean no dep info
				else               res.push_back(::move(reply.verbose_infos[dep_idxs1[i]-1])) ;
			return { res , true/*ok*/ } ;
		}
		if (direct) {
			jerr.proc         = JobExecProc::DepDirect ;
			jerr.comment_exts = CommentExt::Direct     ;
			if (+jerr.files) return { {} , record->report_sync(::move(jerr)).ok==Yes } ;
			else             return { {} , true/*ok*/                                } ;
		}
		FAIL() ;                                                                                            // NO_COV
	}

	void target( ::vector_s&& files , AccessDigest ad , bool no_follow , bool regexpr ) {
		SWEAR(ad.write!=Maybe) ;                                                          // useless, but if necessary, implement a confirmation mecanism
		bool         do_read = +(ad.accesses&FullAccesses) ;
		LockedRecord record  ;
		//
		if (regexpr) throw_unless( ad.write==No , "regexpr and write are exclusive" ) ;
		else         ad.flags.extra_dflags |= ExtraDflag::NoStar ;                        // ignore regexpr based flags if specified specifically
		_chk_files(files) ;
		//
		if (regexpr) {
			::vmap_s<FileInfo> files_ ; for( ::string& f : files ) files_.emplace_back(::move(f),FileInfo()) ;
			record->report_sync( { .proc=JobExecProc::AccessPattern , .comment=Comment::Target , .digest=ad , .date=New , .files=::move(files_) } ) ;
			 return ;
		}
		AutodepSilent                                 as  ;                               // dont report accesses made to establish what to report
		::vmap<Record::Solve<false/*Send*/>,FileInfo> srs ; srs.reserve(files.size()) ;
		for( ::string& f : files ) {
			Record::Solve<false/*Send*/> sr { *record , f , no_follow , do_read , Comment::Target } ;
			FileInfo fi ; if (sr.file_loc<=FileLoc::Repo) fi = {sr.real} ;
			ad.accesses |= sr.accesses ;                                                  // seems pessimistic but sr.accesses does not actually depend on file, only on no_follow, read and write
			srs.emplace_back( ::move(sr) , fi ) ;
		}
		Pdate              now     { New } ;                                              // for perf and trace coherency, targets have same timestamp, possibly after link accesses while solving
		::vmap_s<FileInfo> targets ;
		for( auto& [sr,fi] : srs )
			if ( sr.file_loc<=FileLoc::Repo && !sr.real0 )
				targets.emplace_back( ::move(sr.real) , fi ) ;
		if (+targets)                                                                     // report all non-overlaid targets in a single report
			record->report_access(
				{ .proc=JobExecProc::Access , .comment=Comment::Target , .digest=ad , .date=now , .files=::move(targets) }
			) ;
		for( auto& [sr,fi] : srs )
			if (+sr.real0)                                                                // then report overlaid targets each in its own report
				record->report_access(
					sr.file_loc
				,	{ .proc=JobExecProc::Access , .comment=Comment::Target , .digest=ad , .date=now , .files={{::move(sr.real),fi}} }
				,	sr.file_loc0
				,	::move(sr.real0)
				) ;
		record->send_report() ;
	}

	Bool3 chk_deps( Delay delay , bool sync ) {
		LockedRecord record ;
		Bool3        res    = record->report_sync({ .proc=JobExecProc::ChkDeps , .sync=No|sync , .comment=Comment::CheckDeps , .date=Pdate(New)+delay }).ok ;
		if ( sync && res==Maybe ) ::pause() ; // we have been killed, wait until we actually die
		return res ;
	}

	::vector_s list( Bool3 write , ::optional_s&& dir , ::optional_s&& regexpr ) {
		// report files as seen from cwd
		LockedRecord    record      ;
		::string const& repo_root_s = Record::s_autodep_env().repo_root_s ;
		::optional_s    abs_dir_s   ;
		if (+dir) {
			AutodepSilent                as ;                                                                                // dont report accesses made to establish what to report
			Record::Solve<false/*Send*/> sr { *record , ::copy(*dir) , true/*no_follow*/ , false/*read*/ , Comment::List } ;
			abs_dir_s = mk_glb( with_slash(::move(sr.real)) , repo_root_s ) ;
		}
		//
		::vector_s          res       ;
		::string            abs_cwd_s = cwd_s() ;
		::optional_s        lcl_cwd_s ;           if ( abs_cwd_s.starts_with(repo_root_s) ) lcl_cwd_s = mk_lcl(abs_cwd_s,repo_root_s) ;
		::optional<RegExpr> re        ;           if ( +regexpr                           ) re        = {*regexpr,false/*cache*/}     ;
		//
		for( ::string& f : record->report_sync({ .proc=JobExecProc::List , .sync=Yes , .comment=Comment::List , .digest{.write=write} , .date=New }).files ) {
			::string abs_f = mk_glb( f , repo_root_s ) ;
			//
			if ( +dir && !abs_f.starts_with(*abs_dir_s) ) continue ;
			//
			::string& user_f = abs_f ;                                                                                       // reuse storage
			if ( +lcl_cwd_s && !is_abs(f) ) user_f = mk_lcl( f , *lcl_cwd_s ) ;                                              // else keep abs_f as is
			//
			if ( +regexpr && !re->can_match(user_f) ) continue ;
			//
			res.push_back(::move(user_f)) ;
		}
		return res ;
	}

	::string list_root_s(::string&& dir) {
		// report dir as used as prefix when listing dir
		LockedRecord                 record      ;
		::string const&              repo_root_s = Record::s_autodep_env().repo_root_s                                         ;
		AutodepSilent                as          ;                                                                               // dont report accesses made to establish what to report
		Record::Solve<false/*Send*/> sr          { *record , ::move(dir) , true/*no_follow*/ , false/*read*/ , Comment::List } ;
		::string                     dir_s       = with_slash(::move(sr.real))                                                 ;
		::string                     abs_dir_s   = mk_glb( dir_s , repo_root_s )                                               ;
		::string                     abs_cwd_s   = cwd_s()                                                                     ;
		//
		record->send_report() ;
		if ( abs_cwd_s.starts_with(repo_root_s) && !is_abs(dir_s) ) return mk_lcl( dir_s , mk_lcl(abs_cwd_s,repo_root_s) ) ;
		else                                                        return abs_dir_s                                       ;
	}

	//
	// codec
	//

	static CodecRemoteSide _real( Record& r , ::string const& tab , Comment comment ) {
		throw_unless( +tab  , "table cannot be empty" ) ;
		CodecRemoteSide res ;
		if (is_dir_name(tab)) {
			res = { New , tab } ;
			try                       { res.file_sync = auto_file_sync( res.file_sync , tab ) ;                                                       }
			catch (::string const& e) { throw cat("cannot use codec table : ",e,"\n  consider putting an adequate value in ",AdminDirS,"file_sync") ; }
			SWEAR( +res.file_sync , tab,res.tab ) ;
			return res ;
		}
		AutodepEnv& autodep_env = Record::s_autodep_env_writable() ;                                                                                            // solve lazy file_sync
		//
		if (tab.find('/')==Npos) {
			auto it = autodep_env.codecs.find(tab) ;
			if (it!=autodep_env.codecs.end()) {
				if (!it->second.file_sync)                                                                                                                      // solve lazy
					try                       { it->second.file_sync = auto_file_sync( it->second.file_sync , it->second.tab ) ;                              }
					catch (::string const& e) { throw cat("cannot use codec table : ",e,"\n  consider putting an adequate value in ",AdminDirS,"file_sync") ; }
				res = it->second ;
				SWEAR( +res.file_sync , tab,res.tab ) ;
				return res ;
			}
		}
		//
		Record::Solve<false/*Send*/> sr { r , tab , false/*no_follow*/ , true/*read*/ , Comment::Encode } ;
		throw_unless( sr.file_loc<=FileLoc::Repo , "codec table file must be a local source file" ) ;
		if (+sr.accesses) r.report_access({ .comment=comment , .digest={.accesses=sr.accesses} , .files={{sr.real,{}}} }) ;
		//
		res.tab       = ::move(sr.real)       ;
		res.file_sync = autodep_env.file_sync ;
		SWEAR_PROD( +res.file_sync , tab,res.tab ) ;
		return res ;
	}

	static bool/*retry*/ _retry_codec( Record& r , CodecRemoteSide crs , ::string const& node , Comment c ) {
		if (crs.is_dir()                                                                               ) return false/*retry*/ ; // no retry for external dir tables
		if (FileInfo({Record::s_repo_root_fd(),Codec::CodecFile::s_dir_s(crs.tab)}).tag()==FileTag::Dir) return false/*.    */ ; // if dir exists, it means codec db was initialized
		JobExecRpcReq jerr {
			.proc         = JobExecProc::DepDirect
		,	.sync         = Yes
		,	.comment      = c
		,	.comment_exts = CommentExt::Direct
		,	.digest       {}                                                                                                     // access to node is reported separately
		,	.date         = New
		,	.files        { {node,{}} }
		} ;
		throw_unless( r.report_sync(::move(jerr)).ok==Yes , "no codec table" ) ;
		return true/*retry*/ ;
	}

	// /!\ this function must stay in sync with _create in job_data.cc
	::string decode( ::string&& tab , ::string&& ctx , ::string&& code , uint64_t version ) {
		using namespace Codec ;
		LockedRecord         record     ;
		AutodepSilent        as         ;                                                                                                                           // hide access to codec-file
		CodecRemoteSide      crs        = _real( *record , tab , Comment::Decode ) ;
		CodecFile            cf         { false/*Encode*/ , crs.tab , ctx , code } ; cf.chk() ;
		::string             node       = cf.name()                                ;
		Fd                   rfd        = Record::s_repo_root_fd()                 ;
		SyncGuard            sync_guard { crs.file_sync }                          ;
		AccessDigest         ad         { .accesses=Access::Lnk }                  ; ad.flags.dflags |= Dflag::Codec ; ad.flags.extra_dflags |= ExtraDflag::NoHot ; // beware of default flags, ...
		FileInfo             fi         ;                                                                                                                           // ... dep is guarded
		::optional<::string> res        ;
		//
		throw_unless( !version || version==Version::Codec , "unsupported version (",version,") : must be ",Version::Codec ) ;
		//
		bool          retried = false ;
	Retry :
		try {
			fi = { {rfd,node} } ; throw_unless( fi.tag()==FileTag::Lnk ) ;
			// START_OF_VERSIONING CODEC
			res = AcFd({rfd,node},{.sync_guard=&sync_guard}).read() ;                           // if node exists, it contains the reply
			// END_OF_VERSIONING
		} catch (::string const&) {                                                             // if node does not exist, maybe the table is not initialized
			if ( _retry_codec(*record,crs,node,Comment::Decode) && !retried ) {
				retried = true ;
				goto Retry/*BACKWARD*/ ;
			}
		}
		//
		record->report_access({ .comment=Comment::Decode , .digest=ad , .files={{node,fi}} }) ; // report access after possible update
		record->send_report() ;
		throw_unless( +res , "code ",code," not found in context ",ctx ) ;
		return *res ;
	}

	// /!\ this function must stay in sync with _create in job_data.cc
	::string encode( ::string&& tab , ::string&& ctx , ::string&& val  , uint8_t min_len , uint64_t version ) {
		throw_unless( min_len>=1                      , "min_length (",min_len,") must be at least 1"                      ) ;
		throw_unless( min_len<=Codec::CodecCrc::HexSz , "min_length (",min_len,") must be at most ",Codec::CodecCrc::HexSz ) ;                                 // codes are output in hex, 4 bits/digit
		using namespace Codec ;
		LockedRecord    record     ;
		AutodepSilent   as         ;                                                                                                                           // hide access to codec-file
		CodecRemoteSide crs        = _real( *record , tab , Comment::Encode ) ;
		CodecCrc        crc        { New  , val }                             ;
		::string        crc_base64 = crc.base64()                             ;
		::string        crc_hex    = crc.hex   ()                             ;
		CodecFile       cf         { crs.tab , ctx , crc }                    ; cf.chk() ;
		::string        node       = cf.name()                                ;
		AccessDigest    ad         ;                                            ad.flags.dflags |= Dflag::Codec ; ad.flags.extra_dflags |= ExtraDflag::NoHot ; // beware of default flags
		FileInfo        fi         ;
		::string        res        ;
		::string        msg        ;
		CodecLock       lock       ;                                                                                 // for use with local to ensure server maintenance is not on-going
		SyncGuard       sync_guard { crs.file_sync }                          ;
		Fd              rfd        = Record::s_repo_root_fd()                 ;
		//
		throw_unless( !version || version==Version::Codec , "unsupported version (",version,") : must be ",Version::Codec ) ;
		//
		bool depended = false ;
	Retry :
		try {
			fi = { {rfd,node} , {.sync_guard=&sync_guard} } ;                                                        // get date before access to be pessimistic
			// START_OF_VERSIONING CODEC
			if (fi.tag()==FileTag::Lnk) res = read_lnk( {rfd,node} , &sync_guard ) ;
			if (+res) {
				throw_unless( res.ends_with(DecodeSfx) , "bad encode link" ) ;
				res.resize( res.size() - DecodeSfxSz )                       ;
			} else {
				if (_retry_codec(*record,crs,node,Comment::Encode)) {
					throw_unless( !depended , "cannot use codec file ",cf.file ) ;
					depended = true ;
					goto Retry/*BACKWARD*/ ;
				}
				if ( !crs.is_dir() && !lock ) {
					lock = {rfd,cf.file} ;
					lock.lock_shared( cat(host(),'-',::getpid()) ) ;                                                 // passed id is for debug only
					throw_unless( +lock , "cannot lock codec file ",cf.file ) ;
					goto Retry/*BACKWARD*/ ;
				}
				::string dir_s = CodecFile::s_dir_s(crs.tab) ;
				creat_store( {rfd,dir_s} , crc_base64 , val , crs.umask , &sync_guard ) ;                            // ensure data exist in store
				//
				CodecFile dcf       { false/*encode*/ , crs.tab , ctx , crc_hex.substr(0,min_len) }                                       ;
				::string& code      = dcf.code()                                                                                          ;
				::string  ctx_dir_s = dir_name_s(node)                                                                                    ;
				::string  rel_data  = mk_lcl( cat(dir_s,"store/",substr_view(crc_base64,0,2),'/',substr_view(crc_base64,2)) , ctx_dir_s ) ;
				// find code
				for(; code.size()<crc_hex.size() ; code.push_back(crc_hex[code.size()]) ) {
					::string decode_node = dcf.name() ;
					try {
						sym_lnk( {rfd,decode_node} , rel_data       , {.sync_guard=&sync_guard,.umask=crs.umask} ) ;
						sym_lnk( {rfd,node       } , code+DecodeSfx , {.sync_guard=&sync_guard,.umask=crs.umask} ) ; // create the encode side
						//
						FileInfo stamp_fi { dir_s+"stamp" , {.sync_guard=&sync_guard} } ;        // stamp created links to logical date to ensure proper overwritten detection in lmake engine ...
						touch( {rfd,decode_node} , stamp_fi.date , {.sync_guard=&sync_guard} ) ; // ... if no stamp, date is the epoch, which is fine
						touch( {rfd,node       } , stamp_fi.date , {.sync_guard=&sync_guard} ) ;
						//
						if (!crs.is_dir()) {
							::string new_code = cat(dir_s,"new_codes/",CodecCrc(New,decode_node).base64()) ;
							sym_lnk( {rfd,new_code} , "../"+node , {.sync_guard=&sync_guard} ) ;                               // tell server
						}
						ad.flags.extra_dflags |= ExtraDflag::CreateEncode ;
						record->report_access({ .comment=Comment::Encode , .digest=ad , .files={{decode_node,FileInfo()}} }) ; // report no access, but with create_encode flag
						goto Found ;                                                            // if sym_lnk succeeds, we have created the code (atomicity works even on NFS)
					} catch (::string const& e) {
						::string tgt = read_lnk({rfd,decode_node}) ;
						if (tgt==rel_data) goto Found ;                                         // if decode_node already exists with the correct content, it has been created concurrently
					}
				}
				throw "no available code"s ;
			Found :
				fi  = { {rfd,node} , {.sync_guard=&sync_guard} } ;                              // update date after create
				res = ::move(code)   ;
			}
			// END_OF_VERSIONING
		} catch(::string const& e) {
			msg = e ;
		}
		ad.accesses = Access::Lnk ;
		record->report_access({ .comment=Comment::Encode , .digest=ad , .files={{node,fi}} }) ; // report access after possible create
		record->send_report() ;                                                                 // this includes deps gathered when solving file
		throw_unless( !msg , msg ) ;
		return res ;
	}

}
