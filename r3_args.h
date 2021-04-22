/*! Разбор списка аргументов, совместим с glib

 */
#if !defined(R3_ARGS_H_INCLUDED) && !defined(__G_LIB_H__)
#define R3_ARGS_H_INCLUDED
typedef enum
{
  G_OPTION_ARG_NONE,
  G_OPTION_ARG_STRING,
  G_OPTION_ARG_INT,
  G_OPTION_ARG_CALLBACK,
  G_OPTION_ARG_FILENAME,
  G_OPTION_ARG_STRING_ARRAY,
  G_OPTION_ARG_FILENAME_ARRAY,
  G_OPTION_ARG_DOUBLE,
  G_OPTION_ARG_INT64
} GOptionArg;
typedef enum
{
  G_OPTION_ERROR_UNKNOWN_OPTION,
  G_OPTION_ERROR_BAD_VALUE,
  G_OPTION_ERROR_FAILED
} GOptionError;
typedef enum
{
  G_OPTION_FLAG_HIDDEN		= 1 << 0,
  G_OPTION_FLAG_IN_MAIN		= 1 << 1,
  G_OPTION_FLAG_REVERSE		= 1 << 2,
  G_OPTION_FLAG_NO_ARG		= 1 << 3,
  G_OPTION_FLAG_FILENAME    = 1 << 4,
  G_OPTION_FLAG_OPTIONAL_ARG    = 1 << 5,
  G_OPTION_FLAG_NOALIAS	        = 1 << 6
} GOptionFlags;
#define G_OPTION_REMAINING ""

typedef struct _GOptionEntry GOptionEntry;
struct _GOptionEntry {
  const char *long_name;
  char        short_name;
  int         flags;

  GOptionArg   arg;
  void*     arg_data;

  const char *description;
  const char *arg_description;
};

typedef struct _GOptionContext GOptionContext;
GOptionContext*
        g_option_context_new (char* title);
void    g_option_context_add_main_entries (GOptionContext *context, GOptionEntry *entries, void* nu/*GETTEXT_PACKAGE*/);
void    g_option_context_set_summary (GOptionContext *context, const char *summary);
int     g_option_context_parse (GOptionContext *context, int *argc, char***argv, void* error);
void    g_option_context_free  (GOptionContext *context);
#endif // R3_ARGS_H_INCLUDED

