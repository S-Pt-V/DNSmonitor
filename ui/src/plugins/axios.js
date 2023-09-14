import axios from "axios";
import store from "@/store";
import setting from "@/settings";

axios.defaults.timeout = 5000;
axios.defaults.baseURL = setting.apiurl;
axios.defaults.headers.post["Content-Type"] = "application/json, charset=UTF-8";
axios.defaults.headers.get["Content-Type"] = "application/json";

// 请求拦截器
axios.interceptors.request.use(
    config => {
        if (store.state.user.token) {
            config.headers.Authorization = "Bearer " + store.state.user.token;
            return config;
        }
    },
    error => {
        return Promise.reject(error);
    }
)

// 响应拦截器
axios.interceptors.response.use(
    response => {
        return response;
    },
    error => {
        return Promise.reject(error);
    }
);

// 重写get
function get(url, params = {}) {
    return new Promise((resolve, reject) => {
        axios
            .get(url, {
                params: params
            })
            .then(response => {
                resolve(response.data);
            })
            .catch(err => {
                reject(err);
            });
    });
}

// 重写post
function post(url, data = {}) {
    return new Promise((resolve, reject) => {
        axios.post(url, data).then(
            response => {
                resolve(response.data);
            },
            err => {
                reject(err);
            }
        );
    });
}

// 重写上传
function upload(url, data = {}) {
    var instance = axios.create({
        baseURL: axios.defaults.baseURL,
        timeout: 5000,
        headers: {
            "Content-Type": "multipart/formdata",
            Authorization: "Bearer " + store.state.user.token
        }
    });
    return instance.post(url, data);
}

// 重写下载
function download(url, data = {}) {
    return new Promise((resolve, reject) => {
        axios.post(url, data, { responseType: "blob" }).then(
            response => {
                resolve(response.data);
            },
            err => {
                reject(err);
            }
        );
    });
}

export { get, post, upload, download };
export default {
    install: function(Vue) {
        Vue.prototype.$get = get;
        Vue.prototype.$post = post;
    }
}
