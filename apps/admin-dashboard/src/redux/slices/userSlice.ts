// ADMIN DASHBOARD - Antigravity
// TODO: Implement batch user actions (suspend, reset password)

/**
 * apps/admin-dashboard/src/redux/slices/userSlice.ts
 */
import { createSlice, PayloadAction } from '@reduxjs/toolkit';
import { User } from '../../types';

interface UserState {
  users: User[];
  selectedUser: User | null;
  isLoading: boolean;
}

const initialState: UserState = {
  users: [],
  selectedUser: null,
  isLoading: false,
};

const userSlice = createSlice({
  name: 'users',
  initialState,
  reducers: {
    setUsers: (state, action: PayloadAction<User[]>) => {
      state.users = action.payload;
    },
    setSelectedUser: (state, action: PayloadAction<User | null>) => {
      state.selectedUser = action.payload;
    },
    updateUserInList: (state, action: PayloadAction<User>) => {
      const index = state.users.findIndex((u) => u.id === action.payload.id);
      if (index !== -1) {
        state.users[index] = action.payload;
      }
    },
  },
});

export const { setUsers, setSelectedUser, updateUserInList } = userSlice.actions;
export default userSlice.reducer;
