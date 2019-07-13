#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <wkhtmltox/pdf.h>

typedef struct {
    ngx_str_t name;
    ngx_http_complex_value_t value;
} ngx_http_wkhtmltopdf_settings_t;

typedef struct {
    ngx_array_t *global_settings;
    ngx_array_t *object_settings;
} ngx_http_wkhtmltopdf_loc_conf_t;

typedef struct {
    wkhtmltopdf_global_settings *global_settings;
} ngx_http_wkhtmltopdf_main_conf_t;

ngx_module_t ngx_http_wkhtmltopdf_module;

/*static void progress_changed_callback(wkhtmltopdf_converter *converter, int p) {
    printf("progress_changed_callback: %3d%%\n", p);
    fflush(stdout);
}*/

/*static void phase_changed_callback(wkhtmltopdf_converter *converter) {
    int phase = wkhtmltopdf_current_phase(converter);
    printf("phase_changed_callback: %s\n", wkhtmltopdf_phase_description(converter, phase));
    fflush(stdout);
}*/

static void error_callback(wkhtmltopdf_converter *converter, const char *msg) {
    fprintf(stderr, "error_callback: %s\n", msg);
    fflush(stderr);
}

static void warning_callback(wkhtmltopdf_converter *converter, const char *msg) {
    fprintf(stderr, "warning_callback: %s\n", msg);
    fflush(stderr);
}

/*static void finished_callback(wkhtmltopdf_converter *converter, int p) {
    printf("finished_callback: %3d%%\n", p);
    fflush(stdout);
}*/

static ngx_int_t ngx_http_wkhtmltopdf_handler(ngx_http_request_t *r) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_wkhtmltopdf_handler");
    if (!(r->method & NGX_HTTP_GET)) return NGX_HTTP_NOT_ALLOWED;
    ngx_int_t rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK && rc != NGX_AGAIN) return rc;
    ngx_http_wkhtmltopdf_main_conf_t *mconf = ngx_http_get_module_main_conf(r, ngx_http_wkhtmltopdf_module);
    if (!mconf->global_settings) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!global_settings"); goto ret; }
    ngx_http_wkhtmltopdf_loc_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_wkhtmltopdf_module);
    rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
    if (conf->global_settings && conf->global_settings->nelts) {
        ngx_http_wkhtmltopdf_settings_t *elt = conf->global_settings->elts;
        for (ngx_uint_t i = 0; i < conf->global_settings->nelts; i++) {
            ngx_str_t complex_value;
            if (ngx_http_complex_value(r, &elt[i].value, &complex_value) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_complex_value != NGX_OK"); goto ret; }
//            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "global_settings: %V = %V", &elt[i].name, &complex_value);
            char *name = ngx_pcalloc(r->pool, elt[i].name.len + 1);
            if (!name) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!name"); goto ret; }
            ngx_memcpy(name, elt[i].name.data, elt[i].name.len);
            char *value = ngx_pcalloc(r->pool, complex_value.len + 1);
            if (!value) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!value"); goto ret; }
            ngx_memcpy(value, complex_value.data, complex_value.len);
//            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "global_settings: %s = %s", name, value);
            if (!wkhtmltopdf_set_global_setting(mconf->global_settings, (const char *)name, (const char *)value)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!wkhtmltopdf_set_global_setting"); goto ret; }
        }
    }
    wkhtmltopdf_object_settings *object_settings = wkhtmltopdf_create_object_settings();
    if (!object_settings) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!object_settings"); goto ret; }
    ngx_str_t out = {0, NULL};
    if (conf->object_settings && conf->object_settings->nelts) {
        ngx_http_wkhtmltopdf_settings_t *elt = conf->object_settings->elts;
        for (ngx_uint_t i = 0; i < conf->object_settings->nelts; i++) {
            ngx_str_t complex_value;
            if (ngx_http_complex_value(r, &elt[i].value, &complex_value) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_complex_value != NGX_OK"); goto wkhtmltopdf_destroy_object_settings; }
//            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "object_settings: %V = %V", &elt[i].name, &complex_value);
            char *name = ngx_pcalloc(r->pool, elt[i].name.len + 1);
            if (!name) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!name"); goto wkhtmltopdf_destroy_object_settings; }
            ngx_memcpy(name, elt[i].name.data, elt[i].name.len);
            char *value = ngx_pcalloc(r->pool, complex_value.len + 1);
            if (!value) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!value"); goto wkhtmltopdf_destroy_object_settings; }
            ngx_memcpy(value, complex_value.data, complex_value.len);
//            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "object_settings: %s = %s", name, value);
            if (!wkhtmltopdf_set_object_setting(object_settings, (const char *)name, (const char *)value)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!wkhtmltopdf_set_object_setting"); goto wkhtmltopdf_destroy_object_settings; }
        }
    }
    wkhtmltopdf_converter *converter = wkhtmltopdf_create_converter(mconf->global_settings);
    if (!converter) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!converter"); goto wkhtmltopdf_destroy_object_settings; }
//    wkhtmltopdf_set_progress_changed_callback(converter, progress_changed_callback);
//    wkhtmltopdf_set_phase_changed_callback(converter, phase_changed_callback);
    wkhtmltopdf_set_error_callback(converter, error_callback);
    wkhtmltopdf_set_warning_callback(converter, warning_callback);
//    wkhtmltopdf_set_finished_callback(converter, finished_callback);
    wkhtmltopdf_add_object(converter, object_settings, (const char *)NULL);
    if (!wkhtmltopdf_convert(converter)) goto wkhtmltopdf_destroy_converter;
    const unsigned char *data;
    out.len = wkhtmltopdf_get_output(converter, &data);
    if (!out.len ) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!out.len"); goto wkhtmltopdf_destroy_converter; }
    out.data = ngx_palloc(r->pool, out.len);
    if (out.data) ngx_memcpy(out.data, data, out.len);
wkhtmltopdf_destroy_converter:
    wkhtmltopdf_destroy_converter(converter);
wkhtmltopdf_destroy_object_settings:
    wkhtmltopdf_destroy_object_settings(object_settings);
    if (out.data) {
        ngx_chain_t ch = {.buf = &(ngx_buf_t){.pos = out.data, .last = out.data + out.len, .memory = 1, .last_buf = 1}, .next = NULL};
        ngx_str_set(&r->headers_out.content_type, "application/pdf");
        r->headers_out.status = NGX_HTTP_OK;
        r->headers_out.content_length_n = out.len;
        rc = ngx_http_send_header(r);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "rc = %i", rc);
        ngx_http_weak_etag(r);
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only); else rc = ngx_http_output_filter(r, &ch);
    }
ret:
    return rc;
}

static char *ngx_http_wkhtmltopdf_settings_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    char *p = conf;
    ngx_array_t **a = (ngx_array_t **) (p + cmd->offset);
    if (*a == NGX_CONF_UNSET_PTR) {
        *a = ngx_array_create(cf->pool, 4, sizeof(ngx_http_wkhtmltopdf_settings_t));
        if (!*a) return NGX_CONF_ERROR;
    }
    ngx_http_wkhtmltopdf_settings_t *settings = ngx_array_push(*a);
    if (!settings) return NGX_CONF_ERROR;
    ngx_str_t *value = cf->args->elts;
    settings->name = value[1];
    ngx_http_compile_complex_value_t ccv = {cf, &value[2], &settings->value, 0, 0, 0};
    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) return NGX_CONF_ERROR;
    return NGX_CONF_OK;
}

static char *ngx_http_wkhtmltopdf_convert_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_wkhtmltopdf_handler;
    return NGX_CONF_OK;
}

static ngx_command_t ngx_http_wkhtmltopdf_commands[] = {
  { .name = ngx_string("wkhtmltopdf_global_settings"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
    .set = ngx_http_wkhtmltopdf_settings_set,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_wkhtmltopdf_loc_conf_t, global_settings),
    .post = NULL },
  { .name = ngx_string("wkhtmltopdf_object_settings"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
    .set = ngx_http_wkhtmltopdf_settings_set,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_wkhtmltopdf_loc_conf_t, object_settings),
    .post = NULL },
  { .name = ngx_string("wkhtmltopdf_convert"),
    .type = NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
    .set = ngx_http_wkhtmltopdf_convert_set,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = 0,
    .post = NULL },
    ngx_null_command
};

static void *ngx_http_wkhtmltopdf_create_main_conf(ngx_conf_t *cf) {
    ngx_http_wkhtmltopdf_main_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_wkhtmltopdf_main_conf_t));
    if (!conf) return NGX_CONF_ERROR;
    return conf;
}

static char *ngx_http_wkhtmltopdf_init_main_conf(ngx_conf_t *cf, void *conf) {
    return NGX_CONF_OK;
}

static void *ngx_http_wkhtmltopdf_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_wkhtmltopdf_loc_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_wkhtmltopdf_loc_conf_t));
    if (!conf) return NGX_CONF_ERROR;
    conf->global_settings = NGX_CONF_UNSET_PTR;
    conf->object_settings = NGX_CONF_UNSET_PTR;
    return conf;
}

static char *ngx_http_wkhtmltopdf_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_wkhtmltopdf_loc_conf_t *prev = parent;
    ngx_http_wkhtmltopdf_loc_conf_t *conf = child;
    ngx_conf_merge_ptr_value(conf->global_settings, prev->global_settings, NULL);
    ngx_conf_merge_ptr_value(conf->object_settings, prev->object_settings, NULL);
    return NGX_CONF_OK;
}

static ngx_http_module_t ngx_http_wkhtmltopdf_module_ctx = {
    .preconfiguration = NULL,
    .postconfiguration = NULL,
    .create_main_conf = ngx_http_wkhtmltopdf_create_main_conf,
    .init_main_conf = ngx_http_wkhtmltopdf_init_main_conf,
    .create_srv_conf = NULL,
    .merge_srv_conf = NULL,
    .create_loc_conf = ngx_http_wkhtmltopdf_create_loc_conf,
    .merge_loc_conf = ngx_http_wkhtmltopdf_merge_loc_conf
};

static ngx_int_t ngx_http_wkhtmltopdf_init_process(ngx_cycle_t *cycle) {
    if (!wkhtmltopdf_init(0)) { ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "!wkhtmltopdf_init"); return NGX_ERROR; }
    ngx_http_wkhtmltopdf_main_conf_t *conf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_wkhtmltopdf_module);
    if (conf->global_settings) return NGX_OK;
    if (!(conf->global_settings = wkhtmltopdf_create_global_settings())) { ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "!global_settings"); return NGX_ERROR; }
    return NGX_OK;
}

static void ngx_http_wkhtmltopdf_exit_process(ngx_cycle_t *cycle) {
    ngx_http_wkhtmltopdf_main_conf_t *conf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_wkhtmltopdf_module);
    if (conf->global_settings) wkhtmltopdf_destroy_global_settings(conf->global_settings);
    if (!wkhtmltopdf_deinit()) ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "!wkhtmltopdf_deinit");
}

ngx_module_t ngx_http_wkhtmltopdf_module = {
    NGX_MODULE_V1,
    .ctx = &ngx_http_wkhtmltopdf_module_ctx,
    .commands = ngx_http_wkhtmltopdf_commands,
    .type = NGX_HTTP_MODULE,
    .init_master = NULL,
    .init_module = NULL,
    .init_process = ngx_http_wkhtmltopdf_init_process,
    .init_thread = NULL,
    .exit_thread = NULL,
    .exit_process = ngx_http_wkhtmltopdf_exit_process,
    .exit_master = NULL,
    NGX_MODULE_V1_PADDING
};
