
## 2025-05-15 - Performance Optimization: In-Memory Configuration Cache

**Learning:** Loading and parsing JSON configuration from disk inside a high-frequency monitoring loop causes excessive disk I/O and CPU overhead. Implementing an in-memory cache with thread-safe access and DeepCopy for integrity significantly improves performance and responsiveness.

**Action:** Replaced `config.LoadConfig()` calls inside the `monitorService` loop with a cache-backed `config.GetServiceConfig(name)` call. Implemented an in-memory cache in the `config` package that is automatically updated on `Save` or `Update` operations.
