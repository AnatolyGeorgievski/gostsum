/*! \defgroup _cli_args Разбор аргументов командной строки
    \brief Разбор аргументов командной строки
    \{
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <libgen.h>
#include "r3_args.h"

struct _GOptionContext {
    char* title;
    const char* summary;
    GOptionEntry* entries;
};
/*! \brief создать контекст разбора аргументов */
GOptionContext* g_option_context_new (char* title)
{
    GOptionContext* context = malloc(sizeof(struct _GOptionContext));
    context->title = title;
    context->summary = NULL;
    context->entries=NULL;
    return context;
}
/*! \brief освободить ресурсы связанные с контекстом разбора */
void g_option_context_free (GOptionContext* context)
{
    free(context);
}
/*! \brief сформировать основной набор опций */
void    g_option_context_add_main_entries (GOptionContext *context, GOptionEntry *entries, void* nu/*GETTEXT_PACKAGE*/)
{
    context->entries = entries;
}
void    g_option_context_set_summary (GOptionContext *context, const char *summary)
{
    context->summary = summary;
}

/*! \brief выполнить разбор аргументов командной строки
    Если разбор аргументов прошел успешно, разобранные аргументы удаляются из списка.
 */
int     g_option_context_parse (GOptionContext *context, int *argc, char***argv, void* error)
{
    char **args = *argv;
    int i;
    int count = 1;
    for (i=1; i<*argc; i++)
    {
        char* arg = args[i];
        if (arg[0] == '-'){
            GOptionEntry* entry = context->entries;
            while (entry->long_name != NULL)
            {
                if ((arg[1] == '-' && strcmp(entry->long_name, &arg[2])==0)
                ||  (arg[2] == '\0' && arg[1] == entry->short_name))
                {
                    switch(entry->arg){
                    case G_OPTION_ARG_NONE:
                        if (entry->arg_data) *(int*)entry->arg_data = !(entry->flags & G_OPTION_FLAG_REVERSE);
                        break;
                    case G_OPTION_ARG_INT:
                        i++;
                        if (entry->arg_data && i<*argc) {
                            *(int*)entry->arg_data = atoi(args[i]);
                        }
                        break;
                    case G_OPTION_ARG_STRING:
                    case G_OPTION_ARG_FILENAME:
// TODO возможно требуется преобразование из locale в utf-8
                        i++;
                        if (entry->arg_data && i<*argc)    *(char* *)entry->arg_data = args[i];
                        break;
                    default:
                        break;
                    }
    //                if (arg[2] == '\0')
                        break;
    /*                else {
                        arg++;
                        entry = context->entries;
                        continue;
                    }*/
                }
                entry++;
            }
            if (entry->long_name == NULL){ // разбор опций help и version
                if (arg[1] == '-' && strcmp("help", &arg[2])==0){
extern const char * g_basename(const char *file_name);
                    printf("Usage: %s [OPTION...] %s\n", (char*)basename(args[0])/*g_get_prgname()*/, context->title);
                    if (context->summary) printf("%s\n", context->summary);
                    printf( "\nHelp Options:\n"
                            " --help\t\tShow help options\n"
                            "\nApplication Options:\n");
                    GOptionEntry* entry = context->entries;
                    while (entry->long_name != NULL)
                    {
                        if (entry->short_name) printf(" -%c,", entry->short_name);
                        if (entry->long_name ) printf(" --%s", entry->long_name);
                        if (entry->arg_description) {
                            printf("=%s", entry->arg_description);
                        }
                        if (entry->description) printf(" \t%s\n", entry->description);
                        entry++;
                    }
                    exit (0);
                } else {
                    args[count++] = arg;
//                    printf("undefined option '%s'\n",args[i]);
                }
            }
        } else { // неразобранные аргументы
            args[count++] = arg;
        }
    }
    *argc = count;
    return 1;
}
//! \}

#ifdef TEST_R3_ARGS

#ifndef FALSE
#define FALSE 0
#endif

struct {
    char* input_file;
    char* output_file;
    int port;
    char* host;
    int verbose;
} cli = {
.output_file=NULL,
.input_file=NULL,
.host = "localhost",
.port = 389,
.verbose = FALSE,
};

static GOptionEntry entries[] =
{
  { "input",    'i', 0, G_OPTION_ARG_FILENAME, &cli.input_file, "input file name", "*.h" },
  { "output",   'o', 0, G_OPTION_ARG_FILENAME,  &cli.output_file,   "output file name", "mib_*.c" },
  { "port",     'p', 0, G_OPTION_ARG_INT,       &cli.port,          "port", "389" },
  { "host",     'h', 0, G_OPTION_ARG_STRING,    &cli.host,          "host name", "localhost" },

  { "verbose", 'v', 0,  G_OPTION_ARG_NONE, &cli.verbose, "Be verbose", NULL },
  { NULL }
};

int main(int argc, char *argv[])
{

//  GError *error = NULL;
    GOptionContext *context = g_option_context_new ("- command line interface");
    g_option_context_add_main_entries (context, entries, NULL/*GETTEXT_PACKAGE*/);
    if (!g_option_context_parse (context, &argc, &argv, NULL/*&error*/))
    {
      //printf ("option parsing failed: %s\n", error->message);
      exit (1);
    }
    printf("host:\t%s\n", cli.host);
    printf("port:\t%d\n", cli.port);
    return 0;
}
#endif
