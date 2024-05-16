// Redux store setup was referenced from https://www.youtube.com/watch?v=xfhQk9CRXbY
// and https://redux-toolkit.js.org/tutorials/typescript
import { configureStore } from '@reduxjs/toolkit'  // src/store/slice.ts
import userSliceReducer from './UserSlice'
import UnAuthUserSliceReducer from './UnAuthUserSlice'
import { initialState as userInitialState } from './UserSlice';
import { initialState as unAuthUserInitialState } from './UnAuthUserSlice';


const preloadedState = loadFromLocalStorage();

export const store = configureStore({
    reducer: {
        user: userSliceReducer,
        uaUser: UnAuthUserSliceReducer,
    },
    devTools: true,
    preloadedState,

})

function saveToLocalStorage(state: RootState) {
    try {
      const serializedState = JSON.stringify(state);
      localStorage.setItem('state', serializedState);
    } catch(e) {
      console.error("Could not save state", e);
    }
  }
  
  function mergeWithInitialState(parsedState: any) {
    return {
      user: { ...userInitialState, ...parsedState.user },
      uaUser: { ...unAuthUserInitialState, ...parsedState.uaUser },
    };
  }
  
  function loadFromLocalStorage() {
    try {
      const serializedState = localStorage.getItem('state');
      if (serializedState === null) return undefined;
      const parsedState = JSON.parse(serializedState);
      console.log("Loaded state:", parsedState);
      return mergeWithInitialState(parsedState);
    } catch(e) {
      console.error("Could not load state", e);
      return undefined;
    }
  }
  
  store.subscribe(() => {
    saveToLocalStorage(store.getState());
  });

// Infer the `RootState` and `AppDispatch` types from the store itself
export type RootState = ReturnType<typeof store.getState>
// Inferred type: {posts: PostsState, comments: CommentsState, users: UsersState}
export type AppDispatch = typeof store.dispatch