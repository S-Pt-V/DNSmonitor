<template>
    <nav>
        <v-app-bar app flat clipped-left class="blue darken-4 white--text">
            <v-app-bar-nav-icon class="white--text" @click="show_drawer = !show_drawer"></v-app-bar-nav-icon>
            <v-toolbar-title class="text-uppercase grey--black">
                <span>QHIC</span>
                <span class="font-weight-light">DNSmonitor</span>
            </v-toolbar-title>
            <v-spacer></v-spacer>
        </v-app-bar>
        <!-- <v-navigation-drawer app clipped v-model="show_drawer">
            <v-list>
                <v-list-item v-for="navi in navigation" :key="navi.link" :to="navi.link">
                    <v-list-item-action>
                        <v-icon color="blue darken-4">{{ navi.icon }}</v-icon>
                    </v-list-item-action>
                    <v-list-item-content>
                        <v-list-item-title class="blue--text text--darken-4">
                            <h4>{{ navi.title }}</h4>
                        </v-list-item-title>
                    </v-list-item-content>
                </v-list-item>
            </v-list>
        </v-navigation-drawer> -->
    </nav>
</template>

<script>
export default {
    name: "Usernavbar",
    data: () => ({
        show_drawer: true,
        navigation: [
            { icon: "mdi-home-analytics", title: "首页", link: "/user/index" },
            { icon: "mdi-file-document-multiple-outline", title: "文档", link: "/user/documents" },
            { icon: "mdi-file-cog-outline", title: "工单", link: "/user/worksheets" },
            { icon: "mdi-account", title: "个人信息", link: "/user/accountinfo" },
        ]
    })
}
</script>