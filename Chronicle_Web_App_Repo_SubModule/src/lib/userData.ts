import { getToken } from "@/lib/authenticate";
import { UserData } from "@/store/UserSlice";

type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE';

async function makeApiRequest(url: string, method: HttpMethod, body = null, query = null) {
  const headers = {
    'content-type': 'application/json',
    'Authorization': `JWT ${getToken()}`
  };

  if (query) {
    url += query;
  }

  const options = {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  };

  const res = await fetch(url, options);
  const data = await res.json();

  if (res.status === 200) {
    return data;
  } else {
    throw new Error(`Request failed with status: ${res.status}`);
  }
}


export async function getUser(query = null) {
  const url = `${process.env.NEXT_PUBLIC_API_URL}/user/`;
  return makeApiRequest(url, 'GET', null, query);
}

//getUserByid
export async function getUserById(userId: string) {
  const url = `${process.env.NEXT_PUBLIC_API_URL}/user/${userId}`;
  return makeApiRequest(url, 'GET');
}

// getUserByUsername
export async function getUserByUsername(username: string) {
  const url = `${process.env.NEXT_PUBLIC_API_URL}/user/username/${username}`;
  console.log(url);
  return makeApiRequest(url, 'GET');
}

//getUsernameById
export async function getUsernameById(userId: string) {
  const url = `${process.env.NEXT_PUBLIC_API_URL}/user/usernameById/${userId}`;
  return makeApiRequest(url, 'GET');
}

export async function updateUser(query: string, formData: FormData) {

  console.log(query);

  console.log("calling submitJournalEntry function from inside");
  const url = `${process.env.NEXT_PUBLIC_API_URL}/user/${query}`;
  const token = getToken(); 

  const options = {
    method: 'PUT',
    headers: {
      'Authorization': `JWT ${token}`,
    },
    body: formData, 
  };

  const response = await fetch(url, options);
  if (!response.ok) {
    throw new Error(`Server responded with ${response.status}`);
  }
  const data = await response.json();
  console.log("User data: ", data);
  return data;

}

export async function deleteUser(userId: string) {
  const url = `${process.env.NEXT_PUBLIC_API_URL}/user/${userId}`;
  return makeApiRequest(url, 'DELETE');
}

//Journal Entries

export async function getJournalEntries(query = null) {
  const url = `${process.env.NEXT_PUBLIC_API_URL}/journal-entries/`;
  return makeApiRequest(url, 'GET', null, query);
}
//by user id
export async function getAllJournalEntriesById(userId: string) {
  const url = `${process.env.NEXT_PUBLIC_API_URL}/journal-entries/${userId}`;
  return makeApiRequest(url, 'GET');
}

//getJournalEntryById
//'/api/journal-entries/entry/:entryId'

export async function getJournalEntryById(entryId: string) {
  const url = `${process.env.NEXT_PUBLIC_API_URL}/journal-entries/entry/${entryId}`;
  return makeApiRequest(url, 'GET');
}

export async function submitJournalEntry(id: string , formData: FormData) {

  console.log("calling submitJournalEntry function from inside:", formData);
  formData.append('userId', id);
  console.log(formData);
  const url = `${process.env.NEXT_PUBLIC_API_URL}/journal-entries/`;
  const token = getToken(); 

  const options = {
    method: 'POST',
    headers: {
      'Authorization': `JWT ${token}`,
    },
    body: formData, 
  };

  const res = await fetch(url, options);
  if (res.ok) {
    return await res;
  } else {
    throw new Error(`Failed to upload journal entry: ${res.statusText}`);
  }
}

export async function updateJournalEntry(id: string, formData: FormData, entryId: string) {
  console.log("calling updateJournalEntry function from inside");
  formData.append('userId', id);
  console.log("id: ", id);
  console.log("entryId: ", entryId);
  const url = `${process.env.NEXT_PUBLIC_API_URL}/journal-entries/entry/${entryId}`;
  const token = getToken(); 

  const options = {
    method: 'PUT',
    headers: {
      'Authorization': `JWT ${token}`,
    },
    body: formData, 
  };

  const res = await fetch(url, options);
  if (res.ok) {
    return await res;
  } else {
    throw new Error(`Failed to update journal entry: ${res.statusText}`);
  }
}

export async function deleteJournalEntry(entryId: string) {
  const url = `${process.env.NEXT_PUBLIC_API_URL}/journal-entries/entry/${entryId}`;
  const response = await fetch(url, {
    method: 'DELETE',
  });

  if (!response.ok) {
    throw new Error(`Failed to delete journal entry: ${response.statusText}`);
  }

  const contentType = response.headers.get('content-type');

  if (contentType && contentType.includes('application/json')) {
    return response.json();
  } else {
    throw new Error('Unexpected response from server');
  }
}


//setJournalEntryPrivacy(entryId, privacy)
export async function setJournalEntryPrivacy(entryId: string, privacy: boolean) {
  const url = `${process.env.NEXT_PUBLIC_API_URL}/journal-entries/entry/${entryId}/privacy`;
  
  const body = {
    privacy
  };

  const token = getToken();
  const options = {
    method: 'PUT',
    headers: {
      'content-type': 'application/json',
      'Authorization': `JWT ${token}`
    },
    body: JSON.stringify(body),
  };

  const res = await fetch(url, options);

  if (res.headers.get('Content-Type')?.includes('application/json')) {
    const data = await res.json();
    if (res.status === 200) {
      return data;
    } else {
      throw new Error(`Request failed with status: ${res.status}`);
    }
  } else {
    const text = await res.text();
    if (text === 'Journal entry privacy updated successfully') {
      return text;
    } else {
      throw new Error(`Unexpected response from server: ${text}`);
    }
  }
}

//changePassword

export async function changeUserPassword(id: string, oldPasswordInput: string, updatedPasswordData: any) {
  console.log("calling changeUserPassword API");
  const url = `${process.env.NEXT_PUBLIC_API_URL}/user/change-password/${id}`;
  
  const token = getToken(); 
  
  const options = {
    method: 'PUT',
    headers: {
      'content-type': 'application/json',
      'Authorization': `JWT ${token}`
    },
    body: JSON.stringify({id, oldPasswordInput, updatedPasswordData}),
  };

  const res = await fetch(url, options);
  
  if (res.ok) {
    const data = await res.text(); 
    console.log("User data: ", data);
    return data;
  } else {
    const errorData = await res.text();
    throw new Error(errorData); 
  }
}

//createPassword

export async function createUserPassword(id: string, updatedPasswordData: any) {
  console.log("calling createUserPassword API");
  const url = `${process.env.NEXT_PUBLIC_API_URL}/user/create-password/${id}`;
  
  const token = getToken(); 
  
  const options = {
    method: 'PUT',
    headers: {
      'content-type': 'application/json',
      'Authorization': `JWT ${token}`
    },
    body: JSON.stringify({id, updatedPasswordData}),
  };

  const res = await fetch(url, options);
  console.log("res: ", res);
  
  if (res.ok) {
    const data = await res.text(); 
    console.log("User data: ", data);
    console.log("Finished createUserPassword with Success:", data);
    return data;
  } else {
    const errorData = await res.text();
    console.log("Finished createUserPassword with Error: ", errorData);
    throw new Error(errorData); 
  }
}

export async function addUserToLikes(entryId: string, userId: string) {
  const url = `${process.env.NEXT_PUBLIC_API_URL}/journal-entries/entry/${entryId}/likes/${userId}`;
  const token = getToken();
  const options = {
    method: 'PUT',
    headers: {
      'content-type': 'application/json',
      'Authorization': `JWT ${token}`
    },
  };

  const res = await fetch(url, options);

  if (res.headers.get('Content-Type')?.includes('application/json')) {
    const data = await res.json();
    if (res.status === 200) {
      return data;
    } else {
      throw new Error(`Request failed with status: ${res.status}`);
    }
  } else {
    const text = await res.text();
    if (text === 'User added to likes successfully') {
      return text;
    } else {
      throw new Error(`Unexpected response from server: ${text}`);
    }
  }

}

export async function removeUserFromLikes(entryId: string, userId: string) {
  const url = `${process.env.NEXT_PUBLIC_API_URL}/journal-entries/entry/${entryId}/likes/${userId}`;
  const token = getToken();
  const options = {
    method: 'DELETE',
    headers: {
      'content-type': 'application/json',
      'Authorization': `JWT ${token}`
    },
  };

  const res = await fetch(url, options);

  if (res.headers.get('Content-Type')?.includes('application/json')) {
    const data = await res.json();
    if (res.status === 200) {
      return data;
    } else {
      throw new Error(`Request failed with status: ${res.status}`);
    }
  } else {
    const text = await res.text();
    if (text === 'User removed from likes successfully') {
      return text;
    } else {
      throw new Error(`Unexpected response from server: ${text}`);
    }
  }
}

export async function submitThread(id: string , formData: FormData) {

  formData.append('userId', id);
  const url = `${process.env.NEXT_PUBLIC_API_URL}/forum/`;
  const token = getToken(); 

  const options = {
    method: 'POST',
    headers: {
      'Authorization': `JWT ${token}`,
    },
    body: formData, 
  };

  const res = await fetch(url, options);
  if (res.ok) {
    return await res;
  } else {
    throw new Error(`Failed to create new thread: ${res.statusText}`);
  }
}

export async function getAllThreads() {
  const url = `${process.env.NEXT_PUBLIC_API_URL}/forum`;
  return makeApiRequest(url, 'GET');
}


export async function getThreadById(threadId: string) {
  const url = `${process.env.NEXT_PUBLIC_API_URL}/forum/${threadId}`;
  return makeApiRequest(url, 'GET');
}

export async function getRepliesByThreadId(threadId: string) {
  const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/replies/${threadId}`);
  if (!response.ok) {
    throw new Error('Failed to fetch replies');
  }
  const replies = await response.json();
  return replies;
}

export async function addReply(threadId: string, userId: string, replyContent: string) {
  const url = `${process.env.NEXT_PUBLIC_API_URL}/replies/add`;

  const body = {
    threadId,
    userId,
    content: replyContent,
  };

  const options = {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `JWT ${getToken()}`, 
    },
    body: JSON.stringify(body),
  };

  try {
    const response = await fetch(url, options);

    if (!response.ok) {
      throw new Error(`Server responded with ${response.status}`);
    }

    const responseData = await response.json();
    console.log("Reply added successfully:", responseData);
    return responseData;
  } catch (error) {
    console.error("Error adding reply:", error);
    throw error; 
  }
}

export async function deleteReply(replyId: string) {
  console.log("calling deleteReply function from inside with replyId: ", replyId);
  const url = `${process.env.NEXT_PUBLIC_API_URL}/replies/${replyId}`;
  const response = await fetch(url, {
    method: 'DELETE',
  });

  if (!response.ok) {
    throw new Error(`Failed to delete thread reply: ${response.statusText}`);
  }

  const contentType = response.headers.get('content-type');

  if (contentType && contentType.includes('application/json')) {
    return response.json();
  } else {
    throw new Error('Unexpected response from server');
  }
}  

export async function deleteThread(threadId: string) {
  console.log("calling deleteThread function from inside with threadId: ", threadId);
  const url = `${process.env.NEXT_PUBLIC_API_URL}/forum/${threadId}`;
  const response = await fetch(url, {
    method: 'DELETE',
  });

  if (!response.ok) {
    throw new Error(`Failed to delete thread: ${response.statusText}`);
  }

  const contentType = response.headers.get('content-type');

  if (contentType && contentType.includes('application/json')) {
    return response.json();
  } else {
    throw new Error('Unexpected response from server');
  }
}

// update reply with replyId and replycontent which is reply.body
export async function updateReply(replyId: string, replyContent: string) {
  console.log("calling updateReply function from inside with replyId: ", replyId, "and replyContent: ", replyContent);
  const url = `${process.env.NEXT_PUBLIC_API_URL}/replies/${replyId}`;
  const token = getToken(); 

  const options = {
    method: 'PUT',
    headers: {
      'content-type': 'application/json',
      'Authorization': `JWT ${token}`
    },
    body: JSON.stringify({content: replyContent}),
  };

  const res = await fetch(url, options);
  if (res.ok) {
    return await res;
  } else {
    throw new Error(`Failed to update reply: ${res.statusText}`);
  }
}