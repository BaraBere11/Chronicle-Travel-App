import { PayloadAction, createSlice } from '@reduxjs/toolkit'


export type JournalEntry = {
  FULL_NAME: string,
  USER_NAME: string,
  TITLE: string,
    BODY: string,
    LOCATION: string,
    LONGITUDE: number;
    LATITUDE: number;
    LOCATION_RATING: number,
    DATE: string,
    IS_PRIVATE: boolean,
    ATTACHMENT_IDS: string[],
    _id: string,
    LIKES: string[],
    USER_ID: string,
}


export type UserData = {
  _id: string,
  USER_NAME: string;
  PASSWORD: string;
  CONFIRM_PASSWORD: string;
  EMAIL_ADDRESS: string;
  TERMS: boolean;
  FIRST_NAME: string;
  LAST_NAME: string;
  IS_ACTIVE: boolean;
  DATE_CREATED: string;
  SECURITY_QUESTION: string;
  SECURITY_ANSWER: string;
  JOURNAL_ENTRIES: Array<JournalEntry>;
  PROFILE_IMAGE_ID: string;
  
};

export const initialState: UserData = {  
  _id: '',
  USER_NAME: '',
  PASSWORD: '',
  CONFIRM_PASSWORD: '',
  EMAIL_ADDRESS: '',
  TERMS: false,
  FIRST_NAME: '',
  LAST_NAME: '',
  IS_ACTIVE: false,
  DATE_CREATED: '',
  SECURITY_QUESTION: '',
  SECURITY_ANSWER: '',
  JOURNAL_ENTRIES: [],
  PROFILE_IMAGE_ID: ''
}

export const userSlice = createSlice({
  name: 'user',
  initialState,
  reducers: {
    setUser: (state, action: PayloadAction<Partial<UserData>>) => {
      return {...state, ...action.payload };
    },
    resetUser: () => initialState,
    updateJournalEntryPrivacy: (state, action: PayloadAction<{ entryId: string, privacy: boolean }>) => {
      const { entryId, privacy } = action.payload;
      const entry = state.JOURNAL_ENTRIES.find(entry => entry._id === entryId);
      if (entry) {
        entry.IS_PRIVATE = privacy;
      }
    },

    addUserToJournalEntryLikes: (state, action: PayloadAction<{ entryId: string, userId: string }>) => {
      const { entryId, userId } = action.payload;
      const entry = state.JOURNAL_ENTRIES.find(entry => entry._id === entryId);
      if (entry) {
        entry.LIKES.push(userId);
      }
    },
    removeUserFromJournalEntryLikes: (state, action: PayloadAction<{ entryId: string, userId: string }>) => {
      const { entryId, userId } = action.payload;
      const entry = state.JOURNAL_ENTRIES.find(entry => entry._id === entryId);  
      if (entry) {
        entry.LIKES = entry.LIKES.filter(id => id !== userId);
      }
    },

    //updateJournalEntryObject
    //arguments are username, entryId, newEntryObject
    updateJournalEntryObject: (state, action: PayloadAction<{ entryId: string, newEntryObject: JournalEntry }>) => {
      const { entryId, newEntryObject } = action.payload;
      const entry = state.JOURNAL_ENTRIES.find(entry => entry._id === entryId);
      if (entry) {
        entry.TITLE = newEntryObject.TITLE;
        entry.BODY = newEntryObject.BODY;
        entry.LOCATION = newEntryObject.LOCATION;
        entry.LATITUDE = newEntryObject.LATITUDE; 
        entry.LONGITUDE = newEntryObject.LONGITUDE; 
        entry.DATE = newEntryObject.DATE;
        entry.IS_PRIVATE = newEntryObject.IS_PRIVATE;
        entry.ATTACHMENT_IDS = newEntryObject.ATTACHMENT_IDS;
        entry.LIKES = newEntryObject.LIKES;
      }
    }
  },
})

// Action creators are generated for each case reducer function
export const { setUser, resetUser, updateJournalEntryPrivacy, addUserToJournalEntryLikes, removeUserFromJournalEntryLikes, updateJournalEntryObject} = userSlice.actions;

export default userSlice.reducer;