#ifndef __BPF_TYPES_H__
#define __BPF_TYPES_H__

#define BPF_ANY 0
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_PERF_EVENT_ARRAY 2

typedef unsigned char      __u8;
typedef unsigned short     __u16;
typedef unsigned int       __u32;
typedef unsigned long long __u64;

typedef signed char        __s8;
typedef short              __s16;
typedef int                __s32;
typedef long long          __s64;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;

typedef __u16 __sum16;
typedef __u32 __wsum;

#endif