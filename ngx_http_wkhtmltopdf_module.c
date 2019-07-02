#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <wkhtmltox/pdf.h>

typedef struct {
    ngx_http_complex_value_t *url;
} ngx_http_wkhtmltopdf_loc_conf_t;

ngx_module_t ngx_http_wkhtmltopdf_module;

static char *ngx_str_t_to_char(ngx_pool_t *pool, ngx_str_t s) {
    char *c = ngx_pcalloc(pool, (s.len + 1) * sizeof(char));
    if (!c) return NULL;
    ngx_memcpy(c, s.data, s.len);
    return c;
}

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

static void cleanup(wkhtmltopdf_converter *converter) {
    printf("cleanup\n");
    fflush(stdout);
    wkhtmltopdf_destroy_converter(converter);
    wkhtmltopdf_deinit();
}

static ngx_int_t ngx_http_wkhtmltopdf_handler(ngx_http_request_t *r) {
    if (!(r->method & NGX_HTTP_GET)) return NGX_HTTP_NOT_ALLOWED;
    ngx_int_t rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK && rc != NGX_AGAIN) return rc;
    ngx_str_t url;
    ngx_http_wkhtmltopdf_loc_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_wkhtmltopdf_module);
    if (ngx_http_complex_value(r, conf->url, &url) != NGX_OK) { ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "ngx_http_complex_value != NGX_OK"); return NGX_ERROR; }
    wkhtmltopdf_init(0);
    wkhtmltopdf_global_settings *global_settings = wkhtmltopdf_create_global_settings();
    wkhtmltopdf_object_settings *object_settings = wkhtmltopdf_create_object_settings();
    wkhtmltopdf_set_object_setting(object_settings, "page", ngx_str_t_to_char(r->pool, url));
    wkhtmltopdf_converter *converter = wkhtmltopdf_create_converter(global_settings);
    ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(r->pool, 0);
    if (!cln) { cleanup(converter); return NGX_ERROR; }
    cln->handler = (ngx_pool_cleanup_pt)cleanup;
    cln->data = converter;
    wkhtmltopdf_set_progress_changed_callback(converter, progress_changed_callback);
    wkhtmltopdf_set_phase_changed_callback(converter, phase_changed_callback);
    wkhtmltopdf_set_error_callback(converter, error_callback);
    wkhtmltopdf_set_warning_callback(converter, warning_callback);
    wkhtmltopdf_set_finished_callback(converter, finished_callback);
    wkhtmltopdf_add_object(converter, object_settings, NULL);
    if (!wkhtmltopdf_convert(converter)) return NGX_ERROR;
    const u_char *buf;
    long size = wkhtmltopdf_get_output(converter, &buf);
    ngx_chain_t out = {.buf = &(ngx_buf_t){.pos = (u_char *)buf, .last = (u_char *)buf + size, .memory = 1, .last_buf = 1}, .next = NULL};
    r->headers_out.content_type.len = sizeof("application/pdf") - 1;
    r->headers_out.content_type.data = (u_char *)"application/pdf";
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = size;
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) return rc;
    return ngx_http_output_filter(r, &out);
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
    .offset = offsetof(ngx_http_wkhtmltopdf_loc_conf_t, url),
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
    if (!conf->url) conf->url = prev->url;
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
