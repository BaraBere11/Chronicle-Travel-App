'use client';

import { store } from './store';    // Import the store
import { Provider } from 'react-redux';     // Import the Provider

export const StoreProvider = ({ children }: {children: React.ReactNode}) => {
    return (
        <Provider store={store}>
        {children}
        </Provider>
    );
    }

