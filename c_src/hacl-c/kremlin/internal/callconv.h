#ifndef __KREMLIN_CALLCONV_H
#define __KREMLIN_CALLCONV_H

/******************************************************************************/
/* Some macros to ease compatibility                                          */
/******************************************************************************/

/* We want to generate __cdecl safely without worrying about it being undefined.
 * When using MSVC, these are always defined. When using MinGW, these are
 * defined too. They have no meaning for other platforms, so we define them to
 * be empty macros in other situations. */
#ifndef _MSC_VER
#ifndef __cdecl
#define __cdecl
#endif
#ifndef __stdcall
#define __stdcall
#endif
#ifndef __fastcall
#define __fastcall
#endif
#endif

/* TODO: review these two definitions and understand why they're needed. */
#ifdef __GNUC__
#  define inline __inline__
#endif

/* GCC-specific attribute syntax; everyone else gets the standard C inline
 * attribute. */
#ifdef __GNU_C__
#  ifndef __clang__
#    define force_inline inline __attribute__((always_inline))
#  else
#    define force_inline inline
#  endif
#else
#  define force_inline inline
#endif

#endif
