#ifndef LOG_H
#define LOG_H
#define ENABLE_LOG
#ifdef ENABLE_LOG
#define LOGI(...) logi (__VA_ARGS__)
#define LOGE(...) loge (__VA_ARGS__)
void logi (const char *fmt, ...);
void loge (const char *fmt, ...);
#else
#define LOGI(...)
#endif
#endif /* LOG_H */
