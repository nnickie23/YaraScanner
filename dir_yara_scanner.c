#include <dirent.h>
#include <errno.h>
#include <libgen.h>
#include <linux/limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "cJSON.h"
#include "yara.h"

cJSON *RESULT = NULL;

void make_error(const char* msg)
{
    fprintf(stderr, "Error: %s\n", msg);
    exit(1);
}

char *get_file_name(char *path)
{
    char *ret = NULL;
    ret = basename(path);
    if (ret == NULL)
    {
        make_error("Failed to get file name.\n");
    }
    return (ret);
}

cJSON *json_create_object(char *file)
{
    cJSON *ret = NULL;
    cJSON *name = NULL;
    cJSON *size = NULL;
    cJSON *path = NULL;
    cJSON *date_of_last_modification = NULL;
    cJSON *access_permissions = NULL;
    struct stat st;
    char time[50];
    char permissions[11];
    char buf[PATH_MAX + 1];

    if (stat(file, &st) != 0)
    {
        snprintf(buf, sizeof(buf), "%s.", strerror(errno));
        make_error(buf);
    }

    ret = cJSON_CreateObject();
    if (ret == NULL)
    {
        make_error("Failed to create json object.\n");
    }

    name = cJSON_CreateString(get_file_name(file));
    if (name == NULL)
    {
        make_error("Failed to create json string.\n");
    }

    size = cJSON_CreateNumber(st.st_size);
    if (size == NULL)
    {
        make_error("Failed to create json number.\n");
    }

    path = cJSON_CreateString(file);
    if (path == NULL)
    {
        make_error("Failed to create json string.\n");
    }

    strftime(time, 50, "%Y-%m-%d %H:%M:%S", localtime(&st.st_mtime));
    date_of_last_modification = cJSON_CreateString(time);
    if (date_of_last_modification == NULL)
    {
        make_error("Failed to create json string.\n");
    }

    permissions[0] = (S_ISDIR(st.st_mode)) ? 'd' : '-';
    permissions[1] = (st.st_mode & S_IRUSR) ? 'r' : '-';
    permissions[2] = (st.st_mode & S_IWUSR) ? 'w' : '-';
    permissions[3] = (st.st_mode & S_IXUSR) ? 'x' : '-';
    permissions[4] = (st.st_mode & S_IRGRP) ? 'r' : '-';
    permissions[5] = (st.st_mode & S_IWGRP) ? 'w' : '-';
    permissions[6] = (st.st_mode & S_IXGRP) ? 'x' : '-';
    permissions[7] = (st.st_mode & S_IROTH) ? 'r' : '-';
    permissions[8] = (st.st_mode & S_IWOTH) ? 'w' : '-';
    permissions[9] = (st.st_mode & S_IXOTH) ? 'x' : '-';
    permissions[10] = '\0';

    access_permissions = cJSON_CreateString(permissions);
    if (access_permissions == NULL)
    {
        make_error("Failed to create json string.\n");
    }

    cJSON_AddItemToObject(ret, "name", name);
    cJSON_AddItemToObject(ret, "size", size);
    cJSON_AddItemToObject(ret, "path", path);
    cJSON_AddItemToObject(ret, "date of last modification", date_of_last_modification);
    cJSON_AddItemToObject(ret, "access permissions", access_permissions);

    return (ret);
}

int yr_callback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data)
{
    char *file = (char *) user_data;
    cJSON *cjson_file = NULL;
    cJSON *cjson_path = NULL;
    cJSON *cjson_i = NULL;

    if (message == CALLBACK_MSG_RULE_MATCHING)
    {
        //parse through JSON array, and if there is an object same as file, do not create object.
        cJSON_ArrayForEach(cjson_i, RESULT)
        {
            cjson_path = cJSON_GetObjectItemCaseSensitive(cjson_i, "path");
            if (cJSON_IsString(cjson_path) && strcmp(file, cjson_path->valuestring) == 0)
            {
                return (CALLBACK_CONTINUE);
            }
        }
        cjson_file = json_create_object(file);
        cJSON_AddItemToArray(RESULT, cjson_file);
    }

    if (message == CALLBACK_MSG_SCAN_FINISHED)
    {
        return (CALLBACK_CONTINUE);
    }
    
    return (CALLBACK_CONTINUE);
}

int is_php(char *file_name)
{
    int len;
    
    len = strlen(file_name);
    if(len > 3 && strcmp(&file_name[len - 4], ".php") == 0)
        return (1);
    else
        return (0);
}

int is_regular_file(const char *path)
{
    struct stat st;
    char buf[PATH_MAX + 1];

    if (stat(path, &st) != 0)
    {
        snprintf(buf, sizeof(buf), "%s.", strerror(errno));
        make_error(buf);
    }
    return S_ISREG(st.st_mode);
}

int is_directory(const char *path)
{
    struct stat st;
    char buf[PATH_MAX + 1];

    if (stat(path, &st) != 0)
    {
        snprintf(buf, sizeof(buf), "%s.", strerror(errno));
        make_error(buf);
    }
    return S_ISDIR(st.st_mode);
}

void yr_compiler_callback(int error_level, const char* file_name, int line_number, const YR_RULE* rule,
const char* message, void* user_data)
{
    char buf[PATH_MAX + 1];
    if (error_level == YARA_ERROR_LEVEL_ERROR)
    {
        snprintf(buf, sizeof(buf), "Error at line %d, in file \"%s\".\nMessage: \"%s\".", line_number, file_name, message);
        make_error(buf);
    }
    else if (error_level == YARA_ERROR_LEVEL_WARNING)
    {
        snprintf(buf, sizeof(buf), "Warning at line %d, in file \"%s\".\nMessage: \"%s\".", line_number, file_name, message);
        make_error(buf);
    }
}

void close_file(FILE* file)
{
    fclose(file);
}

int parse_files(char *dirpath,  YR_RULES *rules)
{
    DIR *dir = NULL;
    struct dirent *dirent = NULL;
    char path[PATH_MAX + 1];
    char buf[PATH_MAX + 1];

    if((dir = opendir(dirpath)) == NULL)
    {
        snprintf(buf, sizeof(buf), "Failed to open directory \"%s\".", dirpath);
        make_error(buf);
    }

    while((dirent = readdir(dir)) != NULL)
    {
        if (strcmp(dirent->d_name, ".") != 0 && strcmp(dirent->d_name, "..") != 0)
        {
            strcpy(path, dirpath);
            strcat(path, "/");
            strcat(path, dirent->d_name);

            if (is_regular_file(path) && is_php(dirent->d_name))
            {
                if (yr_rules_scan_file(rules, path, 0, &yr_callback, (void*) path, 0) != ERROR_SUCCESS)
                {
                    make_error("Failed to scan file.\n");
                }
            }

            else if (is_directory(path))
            {
                parse_files(path, rules);
            }
        }
    }
    closedir(dir);
}

void destroy_yara_rules(YR_RULES* rules)
{
    if (yr_rules_destroy(rules) != ERROR_SUCCESS)
    {
        make_error("Failed to destroy rules.");
    }
    if (yr_finalize() != ERROR_SUCCESS)
    {
        make_error("Failed to finalize Yara.");
    }
}

YR_RULES *get_yara_rules(FILE *rule_file, const char *rule_filename)
{
    YR_RULES *ret = NULL;
    YR_COMPILER *compiler = NULL;

    if (yr_initialize() != ERROR_SUCCESS)
    {
        make_error("Failed to initialize Yara.");
    }

    yr_compiler_create(&(compiler));
    yr_compiler_set_callback(compiler, &yr_compiler_callback, 0);
    
    if ((yr_compiler_add_file(compiler, rule_file, NULL,  rule_filename)) != ERROR_SUCCESS)
    {
        make_error("Failed to add rule file to Yara compiler");
    }

    if ((yr_compiler_get_rules(compiler, &(ret))) == ERROR_INSUFFICIENT_MEMORY)
    {
        make_error("Insufficient memory to complete the operation.");
    }

    return (ret);

}

FILE* get_output_file(const char *output_filename)
{
    FILE *ret = NULL;
    char buf[PATH_MAX + 1];
    if (output_filename != NULL)
    {
        ret = fopen(output_filename, "r");
        if (ret != NULL)
        {
            snprintf(buf, sizeof(buf), "\"%s\" already exists.", output_filename);
            make_error(buf);
        }
        else
        {
            ret = fopen(output_filename, "w");
            if (ret == NULL)
            {
                snprintf(buf, sizeof(buf), "cannot create output file \"%s\".\n", output_filename);
                make_error(buf);
            }
        }
    }
    else
    {
        ret = stdout;
    }
    return (ret);
}

FILE *get_rule_file(const char *rule_filename)
{
    FILE *ret = NULL;
    ret = fopen(rule_filename, "r");
    if (ret == NULL)
    {
        make_error("failed to open yara rule file.");
    }
    return(ret);
}

char *get_full_path(const char *file_name)
{
    char ret[PATH_MAX + 1];
    char *ptr = NULL;
    char buf[PATH_MAX + 1];

    ptr = realpath(file_name, ret);
    if (ptr == NULL)
    {
        snprintf(buf, sizeof(buf), "%s",  strerror(errno));
        make_error(buf);
    }

    return (strdup(ret));
}

void json_destroy_result(void)
{
    cJSON_Delete(RESULT);
}

void json_initialize_result(void)
{
    RESULT = cJSON_CreateArray();
    if (RESULT == NULL)
    {
        make_error("failed to create a JSON array.");
    }
}

int main(int argc, char *argv[])
{
    char *dir_path = NULL;
    char *rule_filename = NULL;
    char *output_filename = NULL;
    FILE *output_file = NULL; 
    FILE *rule_file = NULL;
    YR_RULES *rules = NULL;

    if (argc < 3)
    {
        make_error("not enough input arguments.");
    }

    json_initialize_result(); //create json array called RESULT.

    dir_path = get_full_path(argv[1]); //dirpath is an absolute path
    rule_filename = get_full_path(argv[2]);

    if (argc == 4)
        output_filename = argv[3];

    rule_file = get_rule_file(rule_filename);
    output_file = get_output_file(output_filename);
  
    rules = get_yara_rules(rule_file, rule_filename);

    parse_files(dir_path, rules);

    fprintf(output_file, "%s", cJSON_Print(RESULT));

    destroy_yara_rules(rules);

    close_file(rule_file);
    close_file(output_file);

    free(dir_path);
    free(rule_filename);

    json_destroy_result();

    return (0);
}