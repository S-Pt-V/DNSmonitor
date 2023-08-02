<template>
  <v-app>
    <NavBar />
    <v-main>
      <router-view />
    </v-main>
  </v-app>
</template>

<script>
import NavBar from "@/components/NavBar.vue";
import { api_network_getalladdress } from "@/api";
export default {
  name: "App",
  components: {
    NavBar,
  },
  data: () => ({
    addresses: []
  }),
  mounted() {
    // this.GetAllAddr()
  },
  methods: {
    GetAllAddr() {
      api_network_getalladdress().then(res => {
        console.log(res)
      })
    }
  }

};
</script>
