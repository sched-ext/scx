/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __CAKE_QUOTIENT_BPF_H
#define __CAKE_QUOTIENT_BPF_H

/* Upper half of a full unsigned product, with bounded 32-bit limbs. */
static __always_inline u64 cake_mulhi64_portable(u64 x, u64 y)
{
	u64 x0 = (u32)x, x1 = x >> 32, y0 = (u32)y, y1 = y >> 32;
	u64 lo = x0 * y0;
	u64 mid = x1 * y0 + (lo >> 32);
	u64 carry = mid >> 32;

	/* Keep LLVM from reforming an unsupported BPF 128-bit multiply. */
	asm volatile("" : "+r" (carry));
	mid = (u32)mid + x0 * y1;
	return x1 * y1 + carry + (mid >> 32);
}

#ifndef CAKE_QUOTIENT_CLZ
#define CAKE_QUOTIENT_CLZ(x) ((u32)__builtin_clzll(x))
#endif
#ifndef CAKE_QUOTIENT_MULHI
#define CAKE_QUOTIENT_MULHI(x, y) cake_mulhi64_portable(x, y)
#endif

/* Entry i = floor((2^19 - 3*2^8)/(256+i)); generated with integer arithmetic. */
static const u16 cake_recip_seed[256] = {
	2045, 2037, 2029, 2021, 2013, 2005, 1998, 1990,
	1983, 1975, 1968, 1960, 1953, 1946, 1938, 1931,
	1924, 1917, 1910, 1903, 1896, 1889, 1883, 1876,
	1869, 1863, 1856, 1849, 1843, 1836, 1830, 1824,
	1817, 1811, 1805, 1799, 1792, 1786, 1780, 1774,
	1768, 1762, 1756, 1750, 1745, 1739, 1733, 1727,
	1722, 1716, 1710, 1705, 1699, 1694, 1688, 1683,
	1677, 1672, 1667, 1661, 1656, 1651, 1646, 1641,
	1636, 1630, 1625, 1620, 1615, 1610, 1605, 1600,
	1596, 1591, 1586, 1581, 1576, 1572, 1567, 1562,
	1558, 1553, 1548, 1544, 1539, 1535, 1530, 1526,
	1521, 1517, 1513, 1508, 1504, 1500, 1495, 1491,
	1487, 1483, 1478, 1474, 1470, 1466, 1462, 1458,
	1454, 1450, 1446, 1442, 1438, 1434, 1430, 1426,
	1422, 1418, 1414, 1411, 1407, 1403, 1399, 1396,
	1392, 1388, 1384, 1381, 1377, 1374, 1370, 1366,
	1363, 1359, 1356, 1352, 1349, 1345, 1342, 1338,
	1335, 1332, 1328, 1325, 1322, 1318, 1315, 1312,
	1308, 1305, 1302, 1299, 1295, 1292, 1289, 1286,
	1283, 1280, 1276, 1273, 1270, 1267, 1264, 1261,
	1258, 1255, 1252, 1249, 1246, 1243, 1240, 1237,
	1234, 1231, 1228, 1226, 1223, 1220, 1217, 1214,
	1211, 1209, 1206, 1203, 1200, 1197, 1195, 1192,
	1189, 1187, 1184, 1181, 1179, 1176, 1173, 1171,
	1168, 1165, 1163, 1160, 1158, 1155, 1153, 1150,
	1148, 1145, 1143, 1140, 1138, 1135, 1133, 1130,
	1128, 1125, 1123, 1121, 1118, 1116, 1113, 1111,
	1109, 1106, 1104, 1102, 1099, 1097, 1095, 1092,
	1090, 1088, 1086, 1083, 1081, 1079, 1077, 1074,
	1072, 1070, 1068, 1066, 1064, 1061, 1059, 1057,
	1055, 1053, 1051, 1049, 1047, 1044, 1042, 1040,
	1038, 1036, 1034, 1032, 1030, 1028, 1026, 1024,
};

/* Möller–Granlund Algorithm 2: floor((2^128-1)/d) - 2^64, d >= 2^63. */
static __always_inline u64 cake_reciprocal64(u64 d)
{
	u64 d0 = d & 1, d40 = (d >> 24) + 1, d63 = (d >> 1) + d0;
	u64 v0 = cake_recip_seed[(u32)(d >> 55) & 255];
	u64 v1 = (v0 << 11) - ((v0 * v0 * d40) >> 40) - 1;
	u64 v2 = (v1 << 13) + ((v1 * ((1ULL << 60) - v1 * d40)) >> 47);
	u64 e = 0 - v2 * d63 + (v2 >> 1) * d0;
	u64 v3 = (v2 << 31) + (CAKE_QUOTIENT_MULHI(v2, e) >> 1);
	u64 lo = v3 * d, sum = lo + d;
	u64 hi = CAKE_QUOTIENT_MULHI(v3, d);

	return v3 - (hi + d + (sum < lo));
}

/* Single-word reciprocal product underestimates by at most one quotient unit. */
static __always_inline u64 cake_udiv64_recip(u64 numerator, u64 divisor)
{
	u64 normalized, reciprocal, hi, sum, quotient, remainder;
	u32 shift;

	if (!divisor || numerator < divisor)
		return 0;
	if (divisor == 1)
		return numerator;
	shift = CAKE_QUOTIENT_CLZ(divisor) & 63;
	if (!shift)
		return 1;
	if (!(divisor & (divisor - 1)))
		return numerator >> (63 - shift);
	normalized = divisor << shift;
	reciprocal = cake_reciprocal64(normalized);
	hi = CAKE_QUOTIENT_MULHI(numerator, reciprocal);
	sum = numerator + hi;
	quotient = (sum >> (64 - shift)) | ((u64)(sum < numerator) << shift);
	remainder = numerator - quotient * divisor;
	return quotient + (remainder >= divisor);
}

#endif /* __CAKE_QUOTIENT_BPF_H */
