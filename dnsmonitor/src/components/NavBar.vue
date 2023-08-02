<template>
    <nav>
        <v-app-bar app dense clipped-left class="blue darken-4 white--text">
            <!-- <v-app-bar-nav-icon class="white--text" @click="show_drawer = !show_drawer"></v-app-bar-nav-icon> -->
            <v-toolbar-title class="white--text">
                <span>QHIC </span>
                <span class="font-weight-light">DNSmonitor</span>
            </v-toolbar-title>
            <v-spacer></v-spacer>
            <DialogConfig />
            <!-- <v-dialog v-model="dialog" max-width="600px">
                <template v-slot:activator="{ on, attrs }">
                    <v-btn class="white--text" text v-bind="attrs" v-on="on">
                        <v-icon left>mdi-cog</v-icon>
                        <span>Config</span>
                    </v-btn>
                </template>
                <v-card>
                    <v-card-title>
                        <span>Config</span>
                    </v-card-title>

                    <v-card-text>
                        <v-container>
                            <span>监听服务器设置</span>
                            <v-row>
                                <v-col cols="12">
                                    <v-select :items="addresses" label="监听地址"></v-select>
                                </v-col>
                            </v-row>
                            <span>Syslog服务器设置</span>
                            <v-row>
                                <v-col cols="6">
                                    <v-text-field label="IP地址">
                                    </v-text-field>
                                </v-col>
                                <v-col cols="6">
                                    <v-text-field label="端口">
                                    </v-text-field>
                                </v-col>
                            </v-row>
                        </v-container>
                    </v-card-text>

                    <v-card-actions>
                        <v-spacer></v-spacer>
                        <v-btn color="blue darken-4" text @click="dialog = false">
                            Close
                        </v-btn>
                        <v-btn color="blue darken-4" text @click="dialog = false">
                            Save
                        </v-btn>
                    </v-card-actions>
                </v-card>
            </v-dialog> -->
        </v-app-bar>
    </nav>
</template>

<script>
import DialogConfig from "@/components/Configdialog.vue";
export default {
    name: "Usernavbar",
    components: {
        DialogConfig,
    },
    data: () => ({
        // show_drawer: false
    }),
    mounted() {},
    methods: {}
}
</script>