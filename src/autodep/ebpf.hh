// This file is part of the open-lmake distribution (git@github.com:cesar-douady/open-lmake.git)
// Copyright (c) 2023-2026 Doliam
// This program is free software: you can redistribute/modify under the terms of the GPL-v3 (https://www.gnu.org/licenses/gpl-3.0.html).
// This program is distributed WITHOUT ANY WARRANTY, without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

#pragma once

#include "ebpf_client.hh"

#include "disk.hh"
#include "real_path.hh"

struct Gather ;

struct AutodepEbpf {
	struct Consumer {
		// cxtors & co
		void init(Gather&) ;
		// services
		void handle_event( EbpfDaemon::ThreadCtx const& , EbpfEventHdr const& , EbpfDaemon::Path const& file ) ;
	private :
	::pair_s<bool/*in_repo*/> _mk_file( EbpfDaemon::ThreadCtx const& , EbpfEventHdr const& , EbpfDaemon::Path const& ) ;
	Disk::FileInfo            _mk_info(                                EbpfEventHdr const& , ::string const& ={}     ) ;
		// data
		Gather*     _gather = nullptr ;
		RealPathEnv _rpe    ;
		RealPath    _rp     ;
	} ;
	static int/*rc*/ s_prepare_child(void*) ; // must be called from child
	// cxtors & co
	AutodepEbpf() = default ;
	AutodepEbpf(Gather& g) { init(g) ; }
	void init(Gather&) ;
	bool operator+() const { return +ring_buf ; }
	// accesses
	Fd epoll_fd() const { return ring_buf.epoll_fd ; }
	// services
	bool/*done*/ consume() { return ring_buf.consume() ; }
	// data
	EbpfDaemon::RingBuf<Consumer> ring_buf ;
	::vector_s                    roots    ;
} ;

