<template>
    <v-dialog v-model="dialog" max-width="600px">
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
    </v-dialog>
</template>

<script>
import { api_network_getalladdress } from '@/api';
export default {
    name: "Dialog",
    data: () => ({
        dialog: false,
        addresses: []
    }),
    mounted() {
        this.getalladress();
    },
    methods: {
        getalladress() {
            api_network_getalladdress().then(res => {
                console.log(res)
                this.addresses = res;
            })
        }
    }
}</script>
