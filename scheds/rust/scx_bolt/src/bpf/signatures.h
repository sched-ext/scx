/* Copyright (c) David Vernet <void@manifault.com> */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 */
#ifndef __SIGNATURES_H
#define __SIGNATURES_H

/* Domain function signatures */
static struct dom_ctx *domains_try_lookup_ctx(u32 dom_id);
static struct dom_ctx *domains_lookup_ctx(u32 dom_id);

/* Task function signatures */
static struct task_ctx *tasks_try_lookup_ctx(struct task_struct *p);
static struct task_ctx *tasks_lookup_ctx(struct task_struct *p);

/* PCPU signatures */
static struct pcpu_ctx *pcpu_try_lookup_ctx(s32 cpu);
static struct pcpu_ctx *pcpu_lookup_ctx(s32 cpu);
static struct pcpu_ctx *pcpu_lookup_curr_ctx(void);

#endif /* __SIGNATURES_H */
