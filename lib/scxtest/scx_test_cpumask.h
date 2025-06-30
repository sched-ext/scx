#pragma once

struct cpumask;

void scx_test_set_all_cpumask(int cpu);
void scx_test_set_idle_smtmask(int cpu);
void scx_test_set_idle_cpumask(int cpu);
void scx_test_cpumask_set(int cpu, struct cpumask *cpumask);
