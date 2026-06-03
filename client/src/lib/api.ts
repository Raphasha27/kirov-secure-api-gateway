import axios, {
  AxiosInstance,
  AxiosRequestConfig,
  AxiosResponse,
  InternalAxiosRequestConfig,
} from "axios";
import { createHmac } from "node:crypto";

interface TokenStore {
  accessToken: string | null;
  refreshToken: string | null;
}

const tokenStore: TokenStore = {
  accessToken: null,
  refreshToken: null,
};

function signRequest(
  config: InternalAxiosRequestConfig,
  secret: string
): InternalAxiosRequestConfig {
  const method = config.method?.toUpperCase() ?? "GET";
  const path = config.url ?? "/";
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const body = config.data ? JSON.stringify(config.data) : "";
  const payload = [method, path, timestamp, body].join("|");
  const signature = createHmac("sha256", secret).update(payload).digest("hex");

  config.headers.set("X-Request-Timestamp", timestamp);
  config.headers.set("X-Request-Signature", signature);
  return config;
}

const api: AxiosInstance = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000",
  timeout: 30000,
  headers: { "Content-Type": "application/json" },
});

api.interceptors.request.use(
  (config: InternalAxiosRequestConfig) => {
    if (tokenStore.accessToken) {
      config.headers.set("Authorization", `Bearer ${tokenStore.accessToken}`);
    }

    const apiKey = config.headers.get("X-API-Key") as string | undefined;
    if (apiKey) {
      signRequest(config, apiKey);
    }

    return config;
  },
  (error) => Promise.reject(error)
);

let isRefreshing = false;
let failedQueue: Array<{
  resolve: (token: string) => void;
  reject: (error: unknown) => void;
}> = [];

function processQueue(error: unknown, token: string | null = null): void {
  failedQueue.forEach((prom) => {
    if (error) {
      prom.reject(error);
    } else {
      prom.resolve(token!);
    }
  });
  failedQueue = [];
}

api.interceptors.response.use(
  (response: AxiosResponse) => response,
  async (error) => {
    const originalRequest = error.config;

    if (error.response?.status === 429) {
      const retryAfter = parseInt(
        error.response.headers["retry-after"] ?? "1",
        10
      );
      await new Promise((resolve) => setTimeout(resolve, retryAfter * 1000));
      return api(originalRequest);
    }

    if (error.response?.status === 401 && !originalRequest._retry) {
      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          failedQueue.push({
            resolve: (token: string) => {
              originalRequest.headers["Authorization"] = `Bearer ${token}`;
              resolve(api(originalRequest));
            },
            reject,
          });
        });
      }

      originalRequest._retry = true;
      isRefreshing = true;

      try {
        const { data } = await axios.post(
          `${api.defaults.baseURL}/auth/refresh`,
          { refreshToken: tokenStore.refreshToken }
        );
        tokenStore.accessToken = data.accessToken;
        processQueue(null, data.accessToken);
        originalRequest.headers["Authorization"] = `Bearer ${data.accessToken}`;
        return api(originalRequest);
      } catch (refreshError) {
        processQueue(refreshError, null);
        tokenStore.accessToken = null;
        tokenStore.refreshToken = null;
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(error);
  }
);

export function setTokens(accessToken: string, refreshToken: string): void {
  tokenStore.accessToken = accessToken;
  tokenStore.refreshToken = refreshToken;
}

export function clearTokens(): void {
  tokenStore.accessToken = null;
  tokenStore.refreshToken = null;
}

export default api;
