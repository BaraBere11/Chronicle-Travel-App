"use client";
import React, { useState, useEffect, use } from 'react';
import CustomLayout from '@/components/CustomLayout';
import Image from "next/image";
import { addReply, getRepliesByThreadId, getThreadById, getUserById, updateReply} from '@/lib/userData';
import { useSelector } from 'react-redux';
import { RootState } from '@/store/store';
import fetchImage from '@/lib/attachments';
import TopNavBar from '@/components/TopNavBar';
import Link from 'next/link';
import {ArrowCircleLeftIcon, ReplyIcon} from '@heroicons/react/outline';
import { FaRegTrashAlt } from "react-icons/fa";
import { FaPencilAlt } from "react-icons/fa";
import { deleteReply, deleteThread } from '@/lib/userData';
import { useRouter } from 'next/navigation';
import { MapContainer, Marker, TileLayer, Tooltip,Popup } from "react-leaflet"
import "leaflet/dist/leaflet.css"
import "leaflet-defaulticon-compatibility"
import "leaflet-defaulticon-compatibility/dist/leaflet-defaulticon-compatibility.css"
import LeafletMap from '@/components/LeafletMap';


type ThreadByIDProps = {
  params: {
    threadID: string;
  };
};

type Reply = {
  _id: string;
  BODY: string;
  USER_ID: string;
  DATE_CREATED: string;
};

type Thread = {
  LONGITUDE: number | undefined;
  LATITUDE: number;
  _id: string;
  TITLE: string;
  BODY: string;
  USER_ID: string;
  DATE_CREATED: string;
  ATTACHMENT_IDS: string[];
  LOCATION: string;
};

const ThreadById = ({ params }: ThreadByIDProps) => {
  const [threadId] = useState<string>(params.threadID);
  const [replyContent, setReplyContent] = useState<string>('');
  const [replies, setReplies] = useState<Reply[]>([]); // State to store replies
  const user = useSelector((state: RootState) => state.user);
  const [thread, setThread] = useState<Thread | null>(null);
  const [threadOwnerImgSrc, setThreadOwnerImgSrc] = useState('');
  const [threadOwnerUsername, setThreadOwnerUsername] = useState('');
  const [attachmentSrc, setAttachmentSrc] = useState<string>('');
  const [replyUsernames, setReplyUsernames] = useState<Map<string, string>>(new Map());
  const [replyUserPics, setReplyUserPics] = useState<Map<string, string>>(new Map());
  const [deleteReplyConfirmation, setDeleteReplyConfirmation] = useState(false);
  const [replyIdToDelete, setReplyIdToDelete] = useState<string | null>(null);
  const [deleteThreadConfirmation, setDeleteThreadConfirmation] = useState(false);
  const [threadIdToDelete, setThreadIdToDelete] = useState<string | null>(null);
  const [editReplyConfirmation, setEditReplyConfirmation] = useState(false);
  const [replyIdToEdit, setReplyIdToEdit] = useState('');
  const [replyContentToEdit, setReplyContentToEdit] = useState('');
  const [scrollPosition, setScrollPosition] = useState(0);
  const router = useRouter();

  // const [replyOwnerImageSrc, setReplyOwnerImageSrc] = useState<string>('');
  // const [replyOwnerUsername, setReplyOwnerUsername] = useState<string>('');


  const fetchReplies = async () => {
    try {
      const fetchedReplies = await getRepliesByThreadId(threadId);
      setReplies(fetchedReplies);
  
      // Fetch usernames
      const usernames = new Map<string, string>();
      const userPics = new Map<string, string>();
      for (const reply of fetchedReplies) {
        const user = await getUserById(reply.USER_ID);
        usernames.set(reply._id, user.USER_NAME);
  
        const profilePicData = await fetchImage(user.PROFILE_IMAGE_ID);
        userPics.set(reply._id, profilePicData);
      }
      setReplyUsernames(usernames);
      setReplyUserPics(userPics); 
    } catch (error) {
      console.error("Failed to fetch replies:", error);
    }
  };
  
  useEffect(() => {
    fetchReplies();
  }, [threadId]);


  const fetchThread = async () => {
    try {
      const fetchedThread = await getThreadById(threadId);
      setThread(fetchedThread);
    } catch (error) {
      console.error("Failed to fetch thread:", error);
    }
  };
  
  useEffect(() => {
    fetchThread();
  }, [threadId]);

  useEffect(() => {
    const fetchThreadOwnerPic = async () => {
        try {
            let thread = await getThreadById(threadId);
            console.log("Thread USER ID: ", thread.USER_ID)
            let user = await getUserById(thread.USER_ID);
            setThreadOwnerUsername(user.USER_NAME);
            let threadOwnerImgData = await fetchImage(user.PROFILE_IMAGE_ID);
            setThreadOwnerImgSrc(threadOwnerImgData);
        } catch (error) {
            console.error("Failed to fetch data:", error);
            setThreadOwnerImgSrc('');
        }
    };

    fetchThreadOwnerPic();
}, [threadId]);

const getAttachment = async (attachmentId: string) => {
  try {
    const attachment = await fetchImage(attachmentId);
    return attachment;
  } catch (error) {
    console.error("Failed to fetch attachment:", error);
  }
}

useEffect(() => {
  const fetchAttachment = async () => {
    if (thread && thread?.ATTACHMENT_IDS[0]) {
      try {
        const attachment = await getAttachment(thread.ATTACHMENT_IDS[0]);
        setAttachmentSrc(attachment || ''); // Add null check and fallback value
      } catch (error) {
        console.error("Failed to fetch attachment:", error);
      }
    }
  };

  fetchAttachment();
}, [thread]);


const fetchReplyOwnerUserName = async (reply: Reply) => {
  try {
    const user = await getUserById(reply.USER_ID);
    return user.USER_NAME;
  } catch (error) {
    console.error("Failed to fetch user:", error);
  }
}

//handling Reply Deletion

{/* For Conditionally Displaying Delete Reply Confirmation pop-up*/}
const showDeleteReplyConfirmation = (replyId: string) => {
  console.log("Delete Icon clicked");
  setReplyIdToDelete(replyId);
  setDeleteReplyConfirmation(true);
}

{/*  when clicked on No on Delete Reply Confirmation Pop-up */}
const hideDeleteReplyConfirmation = (e: React.MouseEvent<HTMLButtonElement>) => {
  e.preventDefault();
  console.log("Delete pop-up - NO clicked");
  setDeleteReplyConfirmation(false);
}

{/*Delete Reply - when clicked Yes On Delete Reply Confirmation Pop-up */}
const handleDeleteReply = async (e: React.MouseEvent<HTMLButtonElement>) => {
  e.preventDefault(); 
  console.log("Delete pop-up - YES clicked");
  console.log("Reply ID to be deleted: ", replyIdToDelete);

  const reply = replies.find(r => r._id === replyIdToDelete);
  if (reply) {
    console.log("Reply ID: ", reply._id)
    console.log("Reply BODY: ", reply.BODY)
    console.log("Reply USER ID: ", reply.USER_ID)
    console.log("Reply DATE CREATED: ", reply.DATE_CREATED)

    try {
      await deleteReply(reply._id);
      console.log("Reply deleted");
      //hide the pop-up and redirect to thread id page
      setDeleteReplyConfirmation(false);
      //router.push(`/forum/${threadId}`);
      router.push(`/forum/${threadId}`);
      //fetch and load all the replies
      fetchReplies();
    } catch (error) {
      console.error('Failed to delete thread reply: ', error);
    }
  } else {
    console.log("No reply found with the ID to delete");
  }
  
}

//handling Edit Reply
  
{/* For Conditionally Displaying Edit Reply pop-up*/}

const showEditReplyConfirmation = (replyId: string) => {
  console.log("Edit Reply Icon clicked");
  setReplyIdToEdit(replyId);
  setReplyContentToEdit(replies.find(r => r._id === replyId)?.BODY ?? ''); // Set the initial value of the reply content
  setEditReplyConfirmation(true);
}

{/*  when clicked on CANCEL on Edit Reply Pop-up */}

const hideEditReplyConfirmation = (e: React.MouseEvent<HTMLButtonElement>) => {
  e.preventDefault();
  console.log("Edit pop-up - CANCEL clicked");
  setEditReplyConfirmation(false);
}

{/*Edit Reply - when clicked SAVE On Edit Reply Pop-up */}

//to save the scroll position before editing the reply
useEffect(() => {
  if (window.location.pathname === `/forum/${threadId}`) {
    setTimeout(() => {
      window.scrollTo(0, scrollPosition);
    }, 100);
  }
}, [window.location.pathname]);

const handleEditReply = async (e: React.MouseEvent<HTMLButtonElement>) => {
  e.preventDefault(); 
  console.log("Edit pop-up - SAVE clicked");
  console.log("Reply ID to be edited: ", replyIdToEdit);
  const scrollPosition = window.scrollY;

  const reply = replies.find(r => r._id === replyIdToEdit);
  if (reply) {
    console.log("Reply ID: ", reply._id)
    console.log("Reply BODY: ", reply.BODY)
    console.log("EDITED Reply BODY: ", replyContentToEdit)
    console.log("Reply USER ID: ", reply.USER_ID)
    console.log("Reply DATE CREATED: ", reply.DATE_CREATED)

    try {
      await updateReply(reply._id, replyContentToEdit);
      console.log("Reply edited");
      //hide the pop-up and redirect to thread id page
      setEditReplyConfirmation(false);
          // //push to the same thread id page
          // router.push(`/forum/${threadId}`, );
      // Change the URL without causing a page navigation
      history.pushState({}, '', `/forum/${threadId}`);
      //fetch and load all the replies
      fetchReplies();
      // Restore the scroll position
      window.scrollTo(0, scrollPosition);
    } catch (error) {
      console.error('Failed to edit thread reply: ', error);
    }
  } else {
    console.log("No reply found with the ID to edit");
  }
  
}


//handling Thread Deletion

{/* For Conditionally Displaying Delete Thread Confirmation pop-up*/}
const showDeleteThreadConfirmation = (threadId: string) => {
  console.log("Delete Thread Icon clicked");
  setThreadIdToDelete(threadId);
  setDeleteThreadConfirmation(true);
}

{/*  when clicked on No on Delete Thread Confirmation Pop-up */}
const hideDeleteThreadConfirmation = (e: React.MouseEvent<HTMLButtonElement>) => {
  e.preventDefault();
  console.log("Delete Thread pop-up - NO clicked");
  setDeleteThreadConfirmation(false);
}


{/*Delete Thread - when clicked Yes On Delete Thread Confirmation Pop-up */}
const handleDeleteThread = async (e: React.MouseEvent<HTMLButtonElement>) => {
  e.preventDefault(); 
  console.log("Delete Thread pop-up - YES clicked");
  console.log("Thread ID to be deleted: ", threadIdToDelete);

  if (threadIdToDelete) {
    const thread = await getThreadById(threadIdToDelete);
    console.log("Thread ID: ", thread._id)
    console.log("Thread TITLE: ", thread.TITLE)
    console.log("Thread USER ID: ", thread.USER_ID)
    console.log("Thread DATE CREATED: ", thread.DATE_CREATED)

    try {

      //delete all the replies associated with the thread only, not all the replies across all threads
      //fetching all replies associated with the thread
      const repliesToDelete = await getRepliesByThreadId(threadIdToDelete);

      //deleting all fetched replies
      for (const reply of repliesToDelete) {
        await deleteReply(reply._id);
        console.log("Reply deleted with ID: ", reply._id);
      }

      //delete the thread
      await deleteThread(threadIdToDelete);
      console.log("Thread deleted");

      //hide the Thread Deletion Confirmation pop-up
      setDeleteThreadConfirmation(false);
      
      //redirect to forum page
      router.push(`/forum`);

      // Fetch and load all the threads, except the one which is deleted
      if (threadId !== threadIdToDelete) {
        fetchThread();
      }

    } catch (error) {
      console.error('Failed to delete thread: ', error);
    }
  } else {
    console.log("No thread found with the ID to delete");
  }
}


const handleSubmit = async (event: React.MouseEvent<HTMLButtonElement>) => {
  event.preventDefault();

  try {
    await addReply(threadId, user._id, replyContent);
    setReplyContent('');
    fetchReplies();
  } catch (error) {
    console.error("Failed to add reply:", error);
  }
};

  return (
    <>
      <CustomLayout showNavbar>
        <TopNavBar />
        <div className="mb-16">
          <div className="flex items-center ml-6">
              <Link href="/forum">
                <span className="cursor-pointer">
                  <ArrowCircleLeftIcon className="h-12 w-12 mr-4" />
                </span>
              </Link>
              <h2 className="text-2xl font-bold">Back to<span className ="text-green-500"> Forum</span></h2>
            </div>
        <div className="flex flex-col items-center ml-4 mr-4 mt-4">

        <div className="flex flex-col items-center relative w-full">
          {/* Display Thread */}
          <div className="border-[2px] border-green-500 rounded flex flex-col relative w-full">
                <div className="flex items-center justify-between">
                  <div className="flex items-center">
                  <div className="w-16 h-16 ml-2 mt-2 mb-2">
                          {threadOwnerImgSrc ? (
                            <Image
                              src={threadOwnerImgSrc}
                              alt="Profile picture"
                              layout="responsive"
                              width={100}
                              height={100}
                              className="rounded-full object-cover border-2 border-green-500"
                            />
                          ) : (
                            <Image
                              src="/jonathan.jpg"
                              alt="Profile picture"
                              layout="responsive"
                              width={100}
                              height={100}
                              className="rounded-full object-cover border-2 border-green-500"
                            />
                          )}
                    </div>

                    <div className="flex flex-col ml-2 pr-9">
                      <p className="text-sm font-bold">{threadOwnerUsername}</p>
                      
                    </div>

                    {/** If the user is the owner of the thread, display the delete button */}
                    {user._id === thread?.USER_ID ? (
                      <div className='flex text-lg items-center pl-44 pr-2'>
                      <FaRegTrashAlt
                        className='h-7 w-7 text-red-600'
                        onClick={() => showDeleteThreadConfirmation(thread._id)}
                      />
                      </div>
                    ): null 
                    } 
                    </div>
                  </div>

                  {/** Thread Body */}
                  <div className='m-2'>
                    <h1 className="text-xl font-bold p-2">{thread?.TITLE}</h1>
                    <div className="bg-gray-100 text-sm p-2 rounded-md mb-4">
                        <p>{thread?.BODY}</p>
                        </div>
                        <div className="flex items-center justify-between">
                        <p className='text-xs font-bold pl-2 pb-2 text-left'>{thread?.DATE_CREATED.substring(0,10)} {thread?.DATE_CREATED.substring(11,16)}</p>
                          <p className='text-xs font-bold pl-2 pb-2 text-right'>{thread?.LOCATION}</p>
                        </div>

                        {/** if thread.ATTACHMENT_IDS[0] is not null, display the attachment */}
                        {thread?.ATTACHMENT_IDS[0] && (
                          <div className="flex justify-center">
                            <Image
                              src={attachmentSrc}
                              alt="Attachment"
                              layout="responsive"
                              width={100}
                              height={100}
                              />
                         
                              
                          </div>
                        )}
                  </div>

                        {/* MAPS */}
                        <div className="flex items-center justify-between mb-2">
                          <div className="map-container" style={{ position: 'relative', height: '300px', width: '95%', margin: '0 auto', zIndex: 0 }}>

                            {thread?.LATITUDE && thread?.LONGITUDE && (
                              <LeafletMap latitude={thread?.LATITUDE} longitude={thread?.LONGITUDE} />
                            )}
                          </div>
                        </div>
                </div>        
          </div>

          {/* Reply Form */}
          <div className="flex flex-col items-center mt-4">
            <textarea 
              value={replyContent} 
              onChange={(e) => setReplyContent(e.target.value)} 
              placeholder="Write your reply here..." 
              className="textarea textarea-bordered w-full max-w-lg border-2 border-green-500 p-2">

              </textarea>
            
              <button onClick={handleSubmit} className="bg-green-600 hover:bg-green-500 text-white font-bold py-2 px-4 rounded-2xl mt-4">Reply</button>
            
            
          </div>

          {/* Draw a straight green line*/}
          <div className=" w-4/5 h-1 bg-green-500 m-4"></div>

          {/* Display "Replies" title in green*/}
          <h2 className="text-2xl font-bold text-green-500 mt-2">Replies</h2> 

          {/* Display Replies */}
          <div className="mt-4 relative w-full">
            {replies.map((reply) => (
              <div key={reply._id} className="border rounded-md border-green-400 m-4 mt-2">

                <div className="flex items-center justify-between">

                  <div className="flex items-center">

                    <div className="w-16 h-16 ml-2 mt-2">
                    {replyUserPics.get(reply._id) ?? '' ? (
                              <Image

                                src={replyUserPics.get(reply._id) ?? ''}
                                alt="Profile picture"
                                //layout="responsive"
                                width={50}
                                height={50}
                                className="rounded-full object-cover border-2 border-green-500"
                              />
                              ) : (
                                <Image
                                  src="/jonathan.jpg"
                                  alt="Profile picture"
                                  //layout="responsive"
                                  width={50}
                                  height={50}
                                  className="rounded-full object-cover border-2 border-green-500"
                                  />
                                  )}
                           
                      </div>

                      <div className="flex justify-between items-start">
                        <div className="flex flex-col pr-6 mb-4">
                          <p className="text-sm font-semibold">{replyUsernames.get(reply._id)}</p>
                          
                        </div>

                        

                          {/** If the user is the owner of the reply, display the pencil button to be able to edit the reply*/}
                        {user._id === reply?.USER_ID ? (
                          <div className='flex text-lg items-center pl-32 pr-2'>
                            <FaPencilAlt 
                              className='h-6 w-6 text-green-600'
                              onClick={() => showEditReplyConfirmation(reply._id)}
                            />
                          </div>
                          ): null 
                        } 

                          {/** If the user is the owner of the reply, display the delete button */}
                        {user._id === reply?.USER_ID ? (
                          <div className='flex text-lg items-center pl-2 pr-2'>
                            <FaRegTrashAlt
                              className='h-6 w-6 text-red-600'
                              onClick={() => showDeleteReplyConfirmation(reply._id)}
                            />
                          </div>
                          ): null 
                        }
                    </div>
                  </div>

                </div>

                <div className="flex items-center justify-between">
                <p className='text-xs font-bold pl-4 pb-2'>{reply.DATE_CREATED.substring(0,10)} {reply.DATE_CREATED.substring(11,16)}</p>
                  </div>

                <div className="bg-gray-100 text-sm p-2 rounded-md m-2">
                
                  <p className="text-sm font-semibold">{reply.BODY}</p>
                  
                </div>

                

              </div>
            ))}
          </div>
        </div>
        </div>


        {deleteReplyConfirmation &&
          <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full flex justify-center items-center z-10">
            <div className="bg-white p-5 rounded-lg shadow-xl">
                <h2 className="text-lg font-semibold mb-4 text-center">Confirm Reply Deletion</h2>
                <p className="mb-4 justify-center text-center">Are you sure you want <br/> to delete this reply?</p>
                <div className="flex justify-between">
                    <button onClick={hideDeleteReplyConfirmation} className="bg-gray-300 text-gray-700 px-4 py-2 ml-8 rounded hover:bg-gray-400">No</button> 
                    <button onClick={handleDeleteReply} className="bg-red-500 text-white px-4 py-2 mr-8 rounded hover:bg-red-600">Yes</button>
                </div>
            </div>
          </div>  
          }  


        {deleteThreadConfirmation &&
          <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full flex justify-center items-center z-10">
            <div className="bg-white p-5 rounded-lg shadow-xl">
                <h2 className="text-lg font-semibold mb-4 text-center">Confirm Thread Deletion</h2>
                <p className="mb-4 justify-center text-center">Are you sure you want to delete this Thread <br/> and its associated Replies?</p>
                <div className="flex justify-between">
                    <button onClick={hideDeleteThreadConfirmation} className="bg-gray-300 text-gray-700 px-4 py-2 ml-24 rounded hover:bg-gray-400">No</button> 
                    <button onClick={handleDeleteThread} className="bg-red-500 text-white px-4 py-2 mr-24 rounded hover:bg-red-600">Yes</button>
                </div>
            </div>
          </div>  
          }  
         
         {editReplyConfirmation &&
          <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full flex justify-center items-center z-10">
            <div className="bg-white p-5 rounded-lg shadow-xl">
                <h2 className="text-lg font-semibold mb-4 text-center">Edit Your Reply</h2>

                <div className="flex flex-col items-center mt-4">
                  <textarea 
                    value={replyContentToEdit} 
                    onChange={(e) => setReplyContentToEdit(e.target.value)} 
                    className="textarea textarea-bordered h-56 w-64 max-w-lg border-2 border-green-500 p-2">
                  </textarea>
                </div>
                <br />
                <div className="flex justify-between">
                    <button onClick={hideEditReplyConfirmation} className="w-24 py-3 rounded-3xl bg-gray-500 hover:bg-gray-600 px-6 text-xs font-medium uppercase leading-tight text-white shadow-md transition duration-150 ease-in-out hover:shadow-lg focus:shadow-lg focus:outline-none active:shadow-lg">Cancel</button> 
                    <button onClick={handleEditReply} className="w-24 py-3 rounded-3xl bg-green-500 hover:bg-green-600 px-6 text-sm font-medium uppercase leading-tight text-white shadow-md transition duration-150 ease-in-out hover:shadow-lg focus:shadow-lg focus:outline-none active:shadow-lg">Save</button>
                </div>
            </div>
          </div>  
          }  
    
      </CustomLayout>
    </>
  );
};

export default ThreadById;
