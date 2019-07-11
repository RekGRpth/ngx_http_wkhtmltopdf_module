#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <wkhtmltox/pdf.h>

typedef struct {
    ngx_http_complex_value_t *html;
} ngx_http_wkhtmltopdf_loc_conf_t;

ngx_module_t ngx_http_wkhtmltopdf_module;

static void progress_changed_callback(wkhtmltopdf_converter *converter, int p) {
    printf("progress_changed_callback: %3d%%\n", p);
    fflush(stdout);
}

static void phase_changed_callback(wkhtmltopdf_converter *converter) {
    int phase = wkhtmltopdf_current_phase(converter);
    printf("phase_changed_callback: %s\n", wkhtmltopdf_phase_description(converter, phase));
    fflush(stdout);
}

static void error_callback(wkhtmltopdf_converter *converter, const char *msg) {
    fprintf(stderr, "error_callback: %s\n", msg);
    fflush(stderr);
}

static void warning_callback(wkhtmltopdf_converter *converter, const char *msg) {
    fprintf(stderr, "warning_callback: %s\n", msg);
    fflush(stderr);
}

static void finished_callback(wkhtmltopdf_converter *converter, int p) {
    printf("finished_callback: %3d%%\n", p);
    fflush(stdout);
}

static ngx_int_t ngx_http_wkhtmltopdf_handler(ngx_http_request_t *r) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_wkhtmltopdf_handler");
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "wkhtmltopdf_extended_qt = %i", wkhtmltopdf_extended_qt());
    if (!(r->method & NGX_HTTP_GET)) return NGX_HTTP_NOT_ALLOWED;
    ngx_int_t rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK && rc != NGX_AGAIN) return rc;
    ngx_http_wkhtmltopdf_loc_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_wkhtmltopdf_module);
    rc = NGX_ERROR;
    ngx_str_t value, out = {0, NULL};
    if (ngx_http_complex_value(r, conf->html, &value) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_complex_value != NGX_OK"); goto ret; }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "html = %V", &value);
    if (!wkhtmltopdf_init(0)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!wkhtmltopdf_init"); goto ret; }
    wkhtmltopdf_global_settings *global_settings = wkhtmltopdf_create_global_settings();
    if (!global_settings) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!global_settings"); goto wkhtmltopdf_deinit; }
    wkhtmltopdf_object_settings *object_settings = wkhtmltopdf_create_object_settings();
    if (!object_settings) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!object_settings"); goto wkhtmltopdf_destroy_global_settings; }
    char *html = ngx_pcalloc(r->pool, value.len + 1);
    if (!html) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!html"); goto wkhtmltopdf_destroy_global_settings; }
    ngx_memcpy(html, value.data, value.len);
    wkhtmltopdf_set_object_setting(object_settings, "page", (const char *)html);
    wkhtmltopdf_converter *converter = wkhtmltopdf_create_converter(global_settings);
    if (!converter) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!converter"); goto wkhtmltopdf_destroy_object_settings; }
    wkhtmltopdf_set_progress_changed_callback(converter, progress_changed_callback);
    wkhtmltopdf_set_phase_changed_callback(converter, phase_changed_callback);
    wkhtmltopdf_set_error_callback(converter, error_callback);
    wkhtmltopdf_set_warning_callback(converter, warning_callback);
    wkhtmltopdf_set_finished_callback(converter, finished_callback);
    wkhtmltopdf_add_object(converter, object_settings, (const char *)NULL);
    if (!wkhtmltopdf_convert(converter)) goto wkhtmltopdf_destroy_converter;
    const unsigned char *data;
    long len = wkhtmltopdf_get_output(converter, &data);
    if (!len ) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!len"); goto wkhtmltopdf_destroy_converter; }
    out.data = ngx_palloc(r->pool, len);
    if (out.data) ngx_memcpy(out.data, data, len);
wkhtmltopdf_destroy_converter:
    wkhtmltopdf_destroy_converter(converter);
wkhtmltopdf_destroy_object_settings:
    wkhtmltopdf_destroy_object_settings(object_settings);
wkhtmltopdf_destroy_global_settings:
    wkhtmltopdf_destroy_global_settings(global_settings);
wkhtmltopdf_deinit:
    if (!wkhtmltopdf_deinit()) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!wkhtmltopdf_deinit"); goto ret; }
    if (out.data) {
        ngx_chain_t ch = {.buf = &(ngx_buf_t){.pos = out.data, .last = out.data + len, .memory = 1, .last_buf = 1}, .next = NULL};
        ngx_str_set(&r->headers_out.content_type, "application/pdf");
        r->headers_out.status = NGX_HTTP_OK;
        r->headers_out.content_length_n = len;
        rc = ngx_http_send_header(r);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "rc = %i", rc);
        ngx_http_weak_etag(r);
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only); else rc = ngx_http_output_filter(r, &ch);
    }
ret:
    return rc;
}

static char *ngx_http_wkhtmltopdf_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_wkhtmltopdf_handler;
    return ngx_http_set_complex_value_slot(cf, cmd, conf);
}

static ngx_command_t ngx_http_wkhtmltopdf_commands[] = {
  { .name = ngx_string("wkhtmltopdf"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_http_wkhtmltopdf_conf,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_wkhtmltopdf_loc_conf_t, html),
    .post = NULL },
    ngx_null_command
};

static void *ngx_http_wkhtmltopdf_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_wkhtmltopdf_loc_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_wkhtmltopdf_loc_conf_t));
    if (!conf) return NGX_CONF_ERROR;
    return conf;
}

static char *ngx_http_wkhtmltopdf_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_wkhtmltopdf_loc_conf_t *prev = parent;
    ngx_http_wkhtmltopdf_loc_conf_t *conf = child;
    if (!conf->html) conf->html = prev->html;
    return NGX_CONF_OK;
}

static ngx_http_module_t ngx_http_wkhtmltopdf_module_ctx = {
    .preconfiguration = NULL,
    .postconfiguration = NULL,
    .create_main_conf = NULL,
    .init_main_conf = NULL,
    .create_srv_conf = NULL,
    .merge_srv_conf = NULL,
    .create_loc_conf = ngx_http_wkhtmltopdf_create_loc_conf,
    .merge_loc_conf = ngx_http_wkhtmltopdf_merge_loc_conf
};

ngx_module_t ngx_http_wkhtmltopdf_module = {
    NGX_MODULE_V1,
    .ctx = &ngx_http_wkhtmltopdf_module_ctx,
    .commands = ngx_http_wkhtmltopdf_commands,
    .type = NGX_HTTP_MODULE,
    .init_master = NULL,
    .init_module = NULL,
    .init_process = NULL,
    .init_thread = NULL,
    .exit_thread = NULL,
    .exit_process = NULL,
    .exit_master = NULL,
    NGX_MODULE_V1_PADDING
};
