// This file is part of the open-lmake distribution (git@github.com:doliam-xtech/open-lmake.git)
// Copyright (c) 2023-2026 Doliam
// This program is free software: you can redistribute/modify under the terms of the GPL-v3 (https://www.gnu.org/licenses/gpl-3.0.html).
// This program is distributed WITHOUT ANY WARRANTY, without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

// Job side of the ebpf autodep method.
// The kernel (ebpf.bpf.c) reports, for each syscall of the job accessing files of interest :
// - captures : resolved paths (relative to the repo or to a source dir) together with file info before the syscall modifies anything, and traversed symlinks with their target
// - an End event which closes them and carries the syscall number, its result and its args
// Here, we turn that into the same access reports as the other autodep methods do (cf. record.cc, the semantic of each syscall mirrors what is done there).
// Unlike them, we are not synchronous with the job : we may process an access long after it occurred, when files may have been modified, unlinked or renamed.
// So the rule is that we do not look at the disk : what must be known about files comes from the kernel.
// The exceptions are marked with DISK, they are all corner cases (failed syscalls for which the kernel resolved nothing and the error does not tell whether file exists).

#include <sys/stat.h>
#include <sys/wait.h>

#if HAS_32
	#include "world_32.h"
#endif

#include "app.hh"
#include "disk.hh"
#include "process.hh"
#include "time.hh"

#include "record.hh"
#include "syscall_tab.hh"
#include "gather.hh"

#include "ebpf_client.hh"
#include "ebpf_event.h"

#include "ebpf.hh"

#ifndef O_TMPFILE
	#define O_TMPFILE 0 // no check for O_TMPFILE if it does not exist
#endif

using namespace Disk       ;
using namespace Time       ;
using namespace EbpfDaemon ;

static Pdate _now(EbpfEventHdr const& hdr) {
	if (hdr.stamp_ns) return Pdate( New , hdr.stamp_ns ) ;
	else              return        New                  ;
} ;

FileInfo AutodepEbpf::Consumer::_mk_info( EbpfEventHdr const& hdr , ::string const& file ) {
	FileTag tag ;
	switch (hdr.file_kind) {
		case EBPF_FILE_UNKNOWN :                                                  return {file} ; // XXX : ensure file is a dep or we arrive too late (file may have changed since it was accessed)
		case EBPF_FILE_NO_FILE : tag = FileTag::None                            ; break         ;
		case EBPF_FILE_DIR     : tag = FileTag::Dir                             ; break         ;
		case EBPF_FILE_LNK     : tag = FileTag::Lnk                             ; break         ;
		case EBPF_FILE_REG     : tag = hdr.size ? FileTag::Reg : FileTag::Empty ; break         ;
		case EBPF_FILE_EXE     : tag = FileTag::Exe                             ; break         ;
	DF}
	return { hdr.size , {New,hdr.mtime_ns,tag} } ;
}

::pair_s<bool/*in_repo*/> AutodepEbpf::Consumer::_mk_real( ThreadCtx const& ctx , EbpfEventHdr const& hdr , Path const& path ) {
	::string file = path.path ;
	FileLoc  loc  ;
	//
	if ( !(hdr.flags&EBPF_F_DEP_ALL) && hdr.flags&EBPF_F_NO_FOLLOW ) { // we must check if dir is a symlink
		if (!file) return { {} , false/*in_repo*/ } ;
		file = dir_name_s(file) ;
		if (!file) {
			if ( (hdr.kind&EBPF_READDIR) && path.root_id==EBPF_ROOT_ID_REPO ) return { "." , true /*in_repo*/ } ;
			else                                                              return { {}  , false/*.      */ } ;
		}
		file << rm_slash ;
	}
	switch (path.root_id) {
		case EBPF_ROOT_ID_ABS :
			if (!file) return { {} , false/*in_repo*/ } ;
		break ;
		case EBPF_ROOT_ID_REPO :
			if      (+file                 ) file = path.path.substr(1) ;
			else if (hdr.kind==EBPF_READDIR) return { "." , true /*in_repo*/ } ;
			else                             return { {}  , false/*.      */ } ;
		break ;
		default :
			EbpfRootId i = path.root_id-EBPF_ROOT_ID_SRC_DIR ;
			SWEAR( i<_rpe.src_dirs_s.size() , path.root_id,_rpe.src_dirs_s.size() ) ;
			if      ( +file || hdr.kind==EBPF_READDIR ) file = cat(_rpe.src_dirs_s[i],rm_slash,file) ;
			if      ( +file                           ) {}
			else if ( hdr.kind==EBPF_READDIR          ) return { file , false/*in_repo*/ } ;
			else                                        return { {}   , false/*.      */ } ;
	}
	//
	if (hdr.flags&EBPF_F_SEEN_LNK) {
		_rp.tid = ctx.tid ;
		RealPath::SolveReport sr = _rp.solve( file , hdr.flags&EBPF_F_NO_FOLLOW ) ;
		file = ::move(sr.real    ) ;
		loc  =        sr.file_loc  ;
	} else {
		if (!(hdr.flags&EBPF_F_CANON)) file = mk_canon(file) ;
		switch (path.root_id) {
			case EBPF_ROOT_ID_ABS  : tie(file,loc) = _rpe.file_loc(file) ; break ;
			case EBPF_ROOT_ID_REPO : return { file , true /*in_repo*/ } ;
			default                : return { file , false/*.      */ } ;
		}
	}
	if (loc<=FileLoc::Dep) return { file , loc==FileLoc::Repo } ;
	else                   return { {}   , false              } ;
}

void AutodepEbpf::Consumer::init(Gather& g) {
	_gather = &g                      ;
	_rpe    = Record::s_autodep_env() ; _rpe.file_sync = FileSync::None ;
	_rp     = RealPath(_rpe)          ;
}

void AutodepEbpf::Consumer::handle_event( ThreadCtx const& ctx , EbpfEventHdr const& hdr , Path const& path ) {
	SWEAR( hdr.kind>=EBPF_HAS_DATA , hdr.kind ) ;
	throw_if( hdr.kind==EBPF_PANIC , path.path ) ;
	if (!path.path) return ;
	//
	::pair_s<bool/*in_repo*/> real_lcl = _mk_real( ctx , hdr , path           ) ; if (!real_lcl.first) return ;
	FileInfo                  fi       = _mk_info(       hdr , real_lcl.first ) ;
	AccessDigest              ad       ;
	if (real_lcl.second) {
		switch (hdr.kind) {
			case EBPF_RENAME   :
			case EBPF_EXCHANGE : throw_if( fi.tag()==FileTag::Dir , "moving dir ",real_lcl.first," not implemented yet" ) ; break ;
			default            : ;
		}
		if (hdr.flags&EBPF_F_OK)
			switch (hdr.kind) {
				case EBPF_DST      :
				case EBPF_RENAME   :
				case EBPF_EXCHANGE :
				case EBPF_WRITE    :
				case EBPF_UNLINK   : ad.write = Yes ; break ;
			DN}
	}
	if (hdr.kind==EBPF_READDIR  ) ad.read_dir = true ;
	if (hdr.flags&EBPF_F_DEP_ALL) {
		if (  hdr.flags&EBPF_F_DEP_LNK   ) ad.accesses |= Access::Lnk  ;
		if (  hdr.flags&EBPF_F_DEP_REG   ) ad.accesses |= Access::Reg  ;
		if (  hdr.flags&EBPF_F_DEP_STAT  ) ad.accesses |= Access::Stat ;
		if (!(hdr.flags&EBPF_F_NO_FOLLOW)) ad.accesses |= Access::Lnk  ; // we must follow link if it is one
	} else {
		ad.accesses |= Access::Lnk ; // for path resolution, if no_follow, file is actually the dir of the actually accessed file
	}
	_gather->new_access( _now(hdr) , ::move(real_lcl.first) , ad , _mk_info(hdr) , Yes/*late*/ ) ;
}

// runs in the child, just before execve
// /!\ this function must be malloc free as malloc takes a lock that may be held by another thread at the time process is cloned
int/*rc*/ AutodepEbpf::s_prepare_child(void*) {
	RingBufBase::s_start_job() ;
	return 0 ;
}

void AutodepEbpf::init(Gather& gather) {
	for( [[maybe_unused]] int _ : iota(3) ) {
		if (ring_buf.connect_to_daemon()) goto Connected ;
		Child ebpfd {
			.as_session = true
		,	.cmd_line   = { *g_lmake_root_s+"_bin/lmake_ebpfd" , "lmake" }
		,	.stdout     = Child::PipeFd
		} ;
		ebpfd.spawn() ;
		::string reply = ebpfd.stdout.read() ;
		switch (reply[0]) {
			case '0' : ebpfd.wait     () ; break                                             ; // daemon is already running, wait for this new one that will terminate shortly
			case '1' : ebpfd.mk_daemon() ; break                                             ; // daemon has started       , let it live its daemon life
			default  : ebpfd.wait     () ; throw cat("malformed ebpf daemon reply : ",reply) ;
		}
	}
	throw "cannot connect to nor launch daemon"s ;
Connected :
	ring_buf.init() ;
	ring_buf.consumer.init(gather) ;
	//
	AutodepEnv const& ade = Record::s_autodep_env() ;
	/**/                                          RingBufBase::s_add_root(  EBPF_ROOT_ID_REPO      , ade.repo_root_s                           ) ;
	/**/                                          RingBufBase::s_add_root(  EBPF_ROOT_ID_EXTERN    , ade.repo_root_s+PrivateAdminDirS          ) ;
	/**/                                          RingBufBase::s_add_root(  EBPF_ROOT_ID_EXTERN    , ade.tmp_dir_s                             ) ;
	for( size_t i : iota(ade.src_dirs_s.size()) ) RingBufBase::s_add_root( +EBPF_ROOT_ID_SRC_DIR+i , mk_glb(ade.src_dirs_s[i],ade.repo_root_s) ) ;
}
