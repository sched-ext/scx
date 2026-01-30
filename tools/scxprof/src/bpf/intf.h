// Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

#ifndef __INTF_H
#define __INTF_H

struct hints_event {
    int pid;
    int tgid;
    unsigned long long hints;
    unsigned long long timestamp;
};

#endif
