import Vue from "vue";
import App from "./App.vue";
import router from "./router";
import store from "./store";
import vuetify from "./plugins/vuetify";
import Axios from "@/plugins/axios";
import qs from "qs";

Vue.config.productionTip = false;
Vue.prototype.$axios = Axios;
Vue.prototype.$qs = qs;

new Vue({
  Axios,
  router,
  store,
  vuetify,
  render: (h) => h(App),
}).$mount("#app");
