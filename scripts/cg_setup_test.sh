#!/usr/bin/bash

echo "+cpu" > /sys/fs/cgroup/cgroup.subtree_control

# ==========================================================
# Config 01: a single level, half CPU
mkdir -p /sys/fs/cgroup/test01_l1

echo "+cpu" > /sys/fs/cgroup/test01_l1/cgroup.subtree_control

echo "50000 100000" > /sys/fs/cgroup/test01_l1/cpu.max

# -------------
# Test 01-01
# echo $$ > /sys/fs/cgroup/test01_l1/cgroup.procs

# ==========================================================
# Config 02: a single level, two CPUs
mkdir -p /sys/fs/cgroup/test02_l1

echo "+cpu" > /sys/fs/cgroup/test02_l1/cgroup.subtree_control

echo "200000 100000 " > /sys/fs/cgroup/test02_l1/cpu.max

# -------------
# Test 02-01
# echo $$ > /sys/fs/cgroup/test02_l1/cgroup.procs

# ==========================================================
# Config 03: two-level, half CPU
mkdir -p /sys/fs/cgroup/test03_l1
mkdir -p /sys/fs/cgroup/test03_l1/l2-a
mkdir -p /sys/fs/cgroup/test03_l1/l2-b
mkdir -p /sys/fs/cgroup/test03_l1/l2-c

echo "+cpu" > /sys/fs/cgroup/test03_l1/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test03_l1/l2-a/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test03_l1/l2-b/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test03_l1/l2-c/cgroup.subtree_control

echo "50000 100000" > /sys/fs/cgroup/test03_l1/cpu.max
echo "50000 100000" > /sys/fs/cgroup/test03_l1/l2-a/cpu.max
echo "50000 100000" > /sys/fs/cgroup/test03_l1/l2-b/cpu.max
echo "50000 100000" > /sys/fs/cgroup/test03_l1/l2-c/cpu.max

# -------------
# Test 03-01: running on a single cgroup
# echo $$ > /sys/fs/cgroup/test03_l1/l2-a/cgroup.procs

# -------------
# Test 03-02 (l1, l2): running on two cgroups
# echo $$ > /sys/fs/cgroup/test03_l1/l2-a/cgroup.procs
# echo $$ > /sys/fs/cgroup/test03_l1/l2-b/cgroup.procs

# -------------
# Test 03-03: running on three cgroups
# echo $$ > /sys/fs/cgroup/test03_l1/l2-a/cgroup.procs
# echo $$ > /sys/fs/cgroup/test03_l1/l2-b/cgroup.procs
# echo $$ > /sys/fs/cgroup/test03_l1/l2-c/cgroup.procs


# ==========================================================
# Config 04: two-level, two CPUs
mkdir -p /sys/fs/cgroup/test04_l1
mkdir -p /sys/fs/cgroup/test04_l1/l2-a
mkdir -p /sys/fs/cgroup/test04_l1/l2-b

echo "+cpu" > /sys/fs/cgroup/test04_l1/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test04_l1/l2-a/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test04_l1/l2-b/cgroup.subtree_control

echo "200000 100000" > /sys/fs/cgroup/test04_l1/cpu.max
echo "200000 100000" > /sys/fs/cgroup/test04_l1/l2-a/cpu.max
echo "200000 100000" > /sys/fs/cgroup/test04_l1/l2-b/cpu.max

# -------------
# Test 04-01: running on a single cgroup
# echo $$ > /sys/fs/cgroup/test04_l1/l2-a/cgroup.procs

# -------------
# Test 04-02: running on two cgroups
# echo $$ > /sys/fs/cgroup/test04_l1/l2-a/cgroup.procs
# echo $$ > /sys/fs/cgroup/test04_l1/l2-b/cgroup.procs


# ==========================================================
# Config 05: three-level, half CPU
mkdir -p /sys/fs/cgroup/test05_l1
mkdir -p /sys/fs/cgroup/test05_l1/l2-a
mkdir -p /sys/fs/cgroup/test05_l1/l2-a/l3-x
mkdir -p /sys/fs/cgroup/test05_l1/l2-a/l3-y
mkdir -p /sys/fs/cgroup/test05_l1/l2-b

echo "+cpu" > /sys/fs/cgroup/test05_l1/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test05_l1/l2-a/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test05_l1/l2-a/l3-x/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test05_l1/l2-a/l3-y/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test05_l1/l2-b/cgroup.subtree_control

echo "50000 100000" > /sys/fs/cgroup/test05_l1/cpu.max
echo "50000 100000" > /sys/fs/cgroup/test05_l1/l2-a/cpu.max
echo "50000 100000" > /sys/fs/cgroup/test05_l1/l2-a/l3-x/cpu.max
echo "50000 100000" > /sys/fs/cgroup/test05_l1/l2-a/l3-y/cpu.max
echo "50000 100000" > /sys/fs/cgroup/test05_l1/l2-b/cpu.max

# -------------
# Test 05-01: running on a single cgroup at level three
# echo $$ > /sys/fs/cgroup/test05_l1/l2-a/l3-x/cgroup.procs

# -------------
# Test 05-02: running on a single cgroup at level two
# echo $$ > /sys/fs/cgroup/test05_l1/l2-b/cgroup.procs

# -------------
# Test 05-03: running on two cgroups
# echo $$ > /sys/fs/cgroup/test05_l1/l2-a/l3-x/cgroup.procs
# echo $$ > /sys/fs/cgroup/test05_l1/l2-b/cgroup.procs

# ==========================================================
# Config 06: three-level, two CPUs
mkdir -p /sys/fs/cgroup/test06_l1
mkdir -p /sys/fs/cgroup/test06_l1/l2-a
mkdir -p /sys/fs/cgroup/test06_l1/l2-a/l3-x
mkdir -p /sys/fs/cgroup/test06_l1/l2-a/l3-y
mkdir -p /sys/fs/cgroup/test06_l1/l2-b

echo "+cpu" > /sys/fs/cgroup/test06_l1/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test06_l1/l2-a/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test06_l1/l2-a/l3-x/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test06_l1/l2-a/l3-y/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test06_l1/l2-b/cgroup.subtree_control

echo "200000 100000" > /sys/fs/cgroup/test06_l1/cpu.max
echo "200000 100000" > /sys/fs/cgroup/test06_l1/l2-a/cpu.max
echo "200000 100000" > /sys/fs/cgroup/test06_l1/l2-a/l3-x/cpu.max
echo "200000 100000" > /sys/fs/cgroup/test06_l1/l2-a/l3-y/cpu.max
echo "200000 100000" > /sys/fs/cgroup/test06_l1/l2-b/cpu.max

# -------------
# Test 06-01: running on a single cgroup at level three
# echo $$ > /sys/fs/cgroup/test06_l1/l2-a/l3-x/cgroup.procs

# -------------
# Test 06-02: running on a single cgroup at level two
# echo $$ > /sys/fs/cgroup/test06_l1/l2-b/cgroup.procs

# -------------
# Test 06-03: running on two cgroups
# echo $$ > /sys/fs/cgroup/test06_l1/l2-a/l3-x/cgroup.procs
# echo $$ > /sys/fs/cgroup/test06_l1/l2-b/cgroup.procs

# ==========================================================
# Config 07: deep hierarchy (level 8), half CPU
mkdir -p /sys/fs/cgroup/test07_l1
mkdir -p /sys/fs/cgroup/test07_l1/l2-a
mkdir -p /sys/fs/cgroup/test07_l1/l2-a/l3-a
mkdir -p /sys/fs/cgroup/test07_l1/l2-a/l3-a/l4-a
mkdir -p /sys/fs/cgroup/test07_l1/l#	- 8 vs. 8: 70-150% not 200%
2-a/l3-a/l4-a/l5-a
mkdir -p /sys/fs/cgroup/test07_l1/l2-a/l3-a/l4-a/l5-a/l6-a
mkdir -p /sys/fs/cgroup/test07_l1/l2-a/l3-a/l4-a/l5-a/l6-a/l7-a
mkdir -p /sys/fs/cgroup/test07_l1/l2-a/l3-a/l4-a/l5-a/l6-a/l7-a/l8-a

echo "+cpu" > /sys/fs/cgroup/test07_l1/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test07_l1/l2-a/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test07_l1/l2-a/l3-a/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test07_l1/l2-a/l3-a/l4-a/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test07_l1/l2-a/l3-a/l4-a/l5-a/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test07_l1/l2-a/l3-a/l4-a/l5-a/l6-a/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test07_l1/l2-a/l3-a/l4-a/l5-a/l6-a/l7-a/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test07_l1/l2-a/l3-a/l4-a/l5-a/l6-a/l7-a/l8-a/cgroup.subtree_control

echo "50000 100000" > /sys/fs/cgroup/test07_l1/cpu.max
echo "50000 100000" > /sys/fs/cgroup/test07_l1/l2-a/cpu.max
echo "50000 100000" > /sys/fs/cgroup/test07_l1/l2-a/l3-a/cpu.max
echo "50000 100000" > /sys/fs/cgroup/test07_l1/l2-a/l3-a/l4-a/cpu.max
echo "50000 100000" > /sys/fs/cgroup/test07_l1/l2-a/l3-a/l4-a/l5-a/cpu.max
echo "50000 100000" > /sys/fs/cgroup/test07_l1/l2-a/l3-a/l4-a/l5-a/l6-a/cpu.max
echo "50000 100000" > /sys/fs/cgroup/test07_l1/l2-a/l3-a/l4-a/l5-a/l6-a/l7-a/cpu.max
echo "50000 100000" > /sys/fs/cgroup/test07_l1/l2-a/l3-a/l4-a/l5-a/l6-a/l7-a/l8-a/cpu.max

# -------------
# Test 07-01: running on a single cgroup at the leaf level
# echo $$ > /sys/fs/cgroup/test07_l1/l2-a/l3-a/l4-a/l5-a/l6-a/l7-a/l8-a/cgroup.procs

# ==========================================================
# Config 08: deep hierarchy (level 8), 128 CPUs
mkdir -p /sys/fs/cgroup/test08_l1
mkdir -p /sys/fs/cgroup/test08_l1/l2-a
mkdir -p /sys/fs/cgroup/test08_l1/l2-a/l3-a
mkdir -p /sys/fs/cgroup/test08_l1/l2-a/l3-a/l4-a
mkdir -p /sys/fs/cgroup/test08_l1/l2-a/l3-a/l4-a/l5-a
mkdir -p /sys/fs/cgroup/test08_l1/l2-a/l3-a/l4-a/l5-a/l6-a
mkdir -p /sys/fs/cgroup/test08_l1/l2-a/l3-a/l4-a/l5-a/l6-a/l7-a
mkdir -p /sys/fs/cgroup/test08_l1/l2-a/l3-a/l4-a/l5-a/l6-a/l7-a/l8-a

echo "+cpu" > /sys/fs/cgroup/test08_l1/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test08_l1/l2-a/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test08_l1/l2-a/l3-a/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test08_l1/l2-a/l3-a/l4-a/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test08_l1/l2-a/l3-a/l4-a/l5-a/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test08_l1/l2-a/l3-a/l4-a/l5-a/l6-a/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test08_l1/l2-a/l3-a/l4-a/l5-a/l6-a/l7-a/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test08_l1/l2-a/l3-a/l4-a/l5-a/l6-a/l7-a/l8-a/cgroup.subtree_control

echo "12800000 100000" > /sys/fs/cgroup/test08_l1/cpu.max
echo "12800000 100000" > /sys/fs/cgroup/test08_l1/l2-a/cpu.max
echo "12800000 100000" > /sys/fs/cgroup/test08_l1/l2-a/l3-a/cpu.max
echo "12800000 100000" > /sys/fs/cgroup/test08_l1/l2-a/l3-a/l4-a/cpu.max
echo "12800000 100000" > /sys/fs/cgroup/test08_l1/l2-a/l3-a/l4-a/l5-a/cpu.max
echo "12800000 100000" > /sys/fs/cgroup/test08_l1/l2-a/l3-a/l4-a/l5-a/l6-a/cpu.max
echo "12800000 100000" > /sys/fs/cgroup/test08_l1/l2-a/l3-a/l4-a/l5-a/l6-a/l7-a/cpu.max
echo "12800000 100000" > /sys/fs/cgroup/test08_l1/l2-a/l3-a/l4-a/l5-a/l6-a/l7-a/l8-a/cpu.max

# -------------
# Test 08-01: running on a single cgroup at the leaf level
# echo $$ > /sys/fs/cgroup/test08_l1/l2-a/l3-a/l4-a/l5-a/l6-a/l7-a/l8-a/cgroup.procs

# ==========================================================
# Config 09: a single level, half CPU, long period
mkdir -p /sys/fs/cgroup/test09_l1

echo "+cpu" > /sys/fs/cgroup/test09_l1/cgroup.subtree_control

echo "500000 1000000" > /sys/fs/cgroup/test09_l1/cpu.max

# -------------
# Test 09-01
# echo $$ > /sys/fs/cgroup/test09_l1/cgroup.procs

# ==========================================================
# Config 10: a single level, two CPUs, long period
mkdir -p /sys/fs/cgroup/test10_l1

echo "+cpu" > /sys/fs/cgroup/test10_l1/cgroup.subtree_control

echo "2000000 1000000 " > /sys/fs/cgroup/test10_l1/cpu.max

# -------------
# Test 10-01
# echo $$ > /sys/fs/cgroup/test10_l1/cgroup.procs

# ==========================================================
# Config 11: a single level, half CPU, short period
mkdir -p /sys/fs/cgroup/test11_l1

echo "+cpu" > /sys/fs/cgroup/test11_l1/cgroup.subtree_control

echo "5000 10000" > /sys/fs/cgroup/test11_l1/cpu.max

# -------------
# Test 11-01
# echo $$ > /sys/fs/cgroup/test11_l1/cgroup.procs

# ==========================================================
# Config 12: a single level, two CPUs, short period
mkdir -p /sys/fs/cgroup/test12_l1

echo "+cpu" > /sys/fs/cgroup/test12_l1/cgroup.subtree_control

echo "20000 10000 " > /sys/fs/cgroup/test12_l1/cpu.max

# -------------
# Test 12-01
# echo $$ > /sys/fs/cgroup/test12_l1/cgroup.procs

# ==========================================================
# Config 13: a single level, 128 CPU
mkdir -p /sys/fs/cgroup/test13_l1

echo "+cpu" > /sys/fs/cgroup/test13_l1/cgroup.subtree_control

echo "12800000 100000" > /sys/fs/cgroup/test13_l1/cpu.max

# -------------
# Test 13-01
# echo $$ > /sys/fs/cgroup/test13_l1/cgroup.procs

# ==========================================================
# Config 14: two-level, 128 CPU
mkdir -p /sys/fs/cgroup/test14_l1
mkdir -p /sys/fs/cgroup/test14_l1/l2-a
mkdir -p /sys/fs/cgroup/test14_l1/l2-b

echo "+cpu" > /sys/fs/cgroup/test14_l1/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test14_l1/l2-a/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test14_l1/l2-b/cgroup.subtree_control

echo "12800000 100000" > /sys/fs/cgroup/test14_l1/cpu.max
echo "12800000 100000" > /sys/fs/cgroup/test14_l1/l2-a/cpu.max
echo "12800000 100000" > /sys/fs/cgroup/test14_l1/l2-b/cpu.max

# -------------
# Test 14-01: running on a single cgroup
# echo $$ > /sys/fs/cgroup/test14_l1/l2-a/cgroup.procs

# -------------
# Test 14-02: running on two cgroups
# echo $$ > /sys/fs/cgroup/test14_l1/l2-a/cgroup.procs
# echo $$ > /sys/fs/cgroup/test14_l1/l2-b/cgroup.procs

# ==========================================================
# Config 15: two-level, 1 CPU : 4 CPUs
mkdir -p /sys/fs/cgroup/test15_l1
mkdir -p /sys/fs/cgroup/test15_l1/l2-a
mkdir -p /sys/fs/cgroup/test15_l1/l2-b

echo "+cpu" > /sys/fs/cgroup/test15_l1/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test15_l1/l2-a/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test15_l1/l2-b/cgroup.subtree_control

echo "500000 100000" > /sys/fs/cgroup/test15_l1/cpu.max
echo "100000 100000" > /sys/fs/cgroup/test15_l1/l2-a/cpu.max
echo "400000 100000" > /sys/fs/cgroup/test15_l1/l2-b/cpu.max

# -------------
# Test 15-01: running on two cgroups
# echo $$ > /sys/fs/cgroup/test15_l1/l2-a/cgroup.procs
# echo $$ > /sys/fs/cgroup/test15_l1/l2-b/cgroup.procs
