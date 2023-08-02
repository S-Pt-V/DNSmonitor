import { get, post } from "@/plugins/axios"

export function api_network_getalladdress(data) {
    return get("/api/Network/GetAllAddress", data);
}
