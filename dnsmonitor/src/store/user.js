const user = {
    state: {
        token: undefined,
    },
    getters: {
        Token(state) {
            return state.token;
        }
    },
    mutations: {
        Login(state, payload)
        {
            state.token = payload;
        }
    },
    actions: {}
}