import axios from "axios";

const API_BASE_URL = (
  process.env.NEXT_PUBLIC_API_URL || "/api"
).replace(/\/$/, "");

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  withCredentials: true,
});

// Add JWT token in every request
api.interceptors.request.use(
  (config) => {
    const token =
      typeof window !== "undefined" ? localStorage.getItem("token") : null;

    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }

    console.log(
      `[API Request] ${config.method?.toUpperCase()} ${API_BASE_URL}${config.url}`
    );

    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Debug API response/errors (do not log sensitive response data)
api.interceptors.response.use(
  (response) => {
    return response;
  },
  (error) => {
    console.error(
      `[API Error] ${error.config?.url}`,
      error.response?.data?.message || error.message
    );

    return Promise.reject(error);
  }
);

export default api;