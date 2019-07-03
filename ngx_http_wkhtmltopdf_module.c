#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <wkhtmltox/pdf.h>

typedef struct {
    ngx_http_complex_value_t *url;
} ngx_http_wkhtmltopdf_loc_conf_t;

typedef struct {
    ngx_http_request_t *r;
    ngx_str_t url;
    ngx_str_t out;
} ngx_http_wkhtmltopdf_ctx_t;

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

static void *wkhtmltopdf_convert_handler_internal(void *data) {
    ngx_http_wkhtmltopdf_ctx_t *ctx = data;
    ngx_http_request_t *r = ctx->r;
    ngx_connection_t *c = r->connection;
    ngx_http_set_log_request(c->log, r);
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "wkhtmltopdf_convert_handler_internal");
    ngx_http_wkhtmltopdf_loc_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_wkhtmltopdf_module);
    if (ngx_http_complex_value(r, conf->url, &ctx->url) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx_http_complex_value != NGX_OK"); goto ret; }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "url = %V", &ctx->url);
    sleep(10);
    if (ctx->url.data) { ctx->out = ctx->url; goto ret; }
    wkhtmltopdf_init(0);
    wkhtmltopdf_global_settings *global_settings = wkhtmltopdf_create_global_settings();
    if (!global_settings) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "!global_settings"); goto wkhtmltopdf_deinit; }
    wkhtmltopdf_object_settings *object_settings = wkhtmltopdf_create_object_settings();
    if (!object_settings) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "!object_settings"); goto wkhtmltopdf_destroy_global_settings; }
    char *url = ngx_pcalloc(r->pool, ctx->url.len + 1);
    if (!url) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "!url"); goto wkhtmltopdf_destroy_global_settings; }
    ngx_memcpy(url, ctx->url.data, ctx->url.len);
    wkhtmltopdf_set_object_setting(object_settings, "page", (const char *)url);
    wkhtmltopdf_converter *converter = wkhtmltopdf_create_converter(global_settings);
    if (!converter) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "!converter"); goto wkhtmltopdf_destroy_object_settings; }
//    wkhtmltopdf_set_progress_changed_callback(converter, progress_changed_callback);
//    wkhtmltopdf_set_phase_changed_callback(converter, phase_changed_callback);
    wkhtmltopdf_set_error_callback(converter, error_callback);
    wkhtmltopdf_set_warning_callback(converter, warning_callback);
//    wkhtmltopdf_set_finished_callback(converter, finished_callback);
    wkhtmltopdf_add_object(converter, object_settings, NULL);
    if (!wkhtmltopdf_convert(converter)) ctx->out.data = NULL; else {
        const u_char *buf;
        ctx->out.len = wkhtmltopdf_get_output(converter, &buf);
        ctx->out.data = ngx_palloc(r->pool, ctx->out.len);
        if (ctx->out.data) ngx_memcpy(ctx->out.data, buf, ctx->out.len);
    }
    wkhtmltopdf_destroy_converter(converter);
wkhtmltopdf_destroy_object_settings:
    wkhtmltopdf_destroy_object_settings(object_settings);
wkhtmltopdf_destroy_global_settings:
    wkhtmltopdf_destroy_global_settings(global_settings);
wkhtmltopdf_deinit:
    wkhtmltopdf_deinit();
ret:
    return NULL;
}

static void wkhtmltopdf_convert_handler(void *data, ngx_log_t *log) {
    wkhtmltopdf_convert_handler_internal(data);
}

static void wkhtmltopdf_convert_event_handler(ngx_event_t *ev) {
    ngx_http_wkhtmltopdf_ctx_t *ctx = ev->data;
    ngx_http_request_t *r = ctx->r;
    ngx_connection_t *c = r->connection;
    ngx_http_set_log_request(c->log, r);
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "wkhtmltopdf_convert_event_handler");
    r->main->blocked--;
    ngx_int_t rc = NGX_ERROR;
    if (ctx->out.data) {
        ngx_chain_t out = {.buf = &(ngx_buf_t){.pos = ctx->out.data, .last = ctx->out.data + ctx->out.len, .memory = 1, .last_buf = 1}, .next = NULL};
        ngx_str_set(&r->headers_out.content_type, "application/pdf");
        r->headers_out.status = NGX_HTTP_OK;
        r->headers_out.content_length_n = ctx->out.len;
        rc = ngx_http_send_header(r);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "rc = %i", rc);
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only); else rc = ngx_http_output_filter(r, &out);
    }
    ngx_http_finalize_request(r, rc);
}

static ngx_int_t ngx_http_wkhtmltopdf_handler(ngx_http_request_t *r) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_wkhtmltopdf_handler");
    if (!(r->method & NGX_HTTP_GET)) return NGX_HTTP_NOT_ALLOWED;
    ngx_int_t rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK && rc != NGX_AGAIN) return rc;
    ngx_http_core_loc_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    ngx_thread_pool_t *tp = conf->thread_pool;
    if (!tp) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!tp"); return NGX_ERROR; }
    ngx_thread_task_t *task = ngx_thread_task_alloc(r->pool, sizeof(ngx_http_wkhtmltopdf_ctx_t));
    if (!task) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!task"); return NGX_ERROR; }
    task->handler = wkhtmltopdf_convert_handler;
    ngx_http_wkhtmltopdf_ctx_t *ctx = task->ctx;
    ctx->r = r;
    task->event.handler = wkhtmltopdf_convert_event_handler;
    task->event.data = ctx;
    if (ngx_thread_task_post(tp, task) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_thread_task_post != NGX_OK"); return NGX_ERROR; }
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_thread_task_post == NGX_OK");
    r->main->blocked++;
    r->count++;
    return NGX_OK;
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
