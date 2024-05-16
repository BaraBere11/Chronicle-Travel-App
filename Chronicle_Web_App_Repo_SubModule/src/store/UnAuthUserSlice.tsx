import { PayloadAction, createSlice } from '@reduxjs/toolkit'

export type unAuthUserData = {
    _id: string,
    USER_NAME: string;
    EMAIL_ADDRESS: string;
    SECURITY_QUESTION: string;
    SECURITY_ANSWER: string;
};

export const initialState: unAuthUserData = {  
    _id: '',
    USER_NAME: '',
    EMAIL_ADDRESS: '',
    SECURITY_QUESTION: '',
    SECURITY_ANSWER: '',
  }

export const UnAuthUserSlice = createSlice({
name: 'user',
initialState,
reducers: {
    setUnAuthUser: (state, action: PayloadAction<Partial<unAuthUserData>>)=> {
    return {...state, ...action.payload };
    },
    resetUnAuthUser: () => initialState,
}
})
  
// Action creators are generated for each case reducer function
export const { setUnAuthUser, resetUnAuthUser } = UnAuthUserSlice.actions;

export default UnAuthUserSlice.reducer;