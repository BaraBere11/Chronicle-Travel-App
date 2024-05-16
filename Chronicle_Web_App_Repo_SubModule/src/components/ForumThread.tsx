'use client';

import React, { useEffect, useState } from 'react';
import { MdOutlineForum } from "react-icons/md";
import { MdForum } from "react-icons/md";
import { IoChatbubble } from "react-icons/io5";
import Link from 'next/link';
import { getRepliesByThreadId } from '@/lib/userData';
import { getUsernameById } from '@/lib/userData';


type Thread = {
    _id: string;
    TITLE: string;
    BODY: string;
    USER_ID: string;
    DATE_CREATED: string;
    ATTACHMENT_IDS: string[];
    LOCATION: string;
    };
    interface Reply {
        _id: string;
      }
interface PostProps {
    thread: Thread;
}



const ForumThread: React.FC<PostProps> = ({ thread }) => {

 //create a thread object for testing/dev purposes
    // const thread = {
    //     _id: "8675309",
    //     TITLE: "Test Thread Title is a real long run on sentence that is way too long and way too...",
    //     BODY: "This is a test thread. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Lorem ipsum dolor. Lorem ipsum magnus. Repeat and go on and on and on.",
    //     USER_ID: "Created by FetchUsernamebyID",
    //     DATE_CREATED: "2021-10-01",
    //     ATTACHMENT_IDS: [],
    //     REPLY_IDS: ["12345", "67890", "54321", "09876", "54321", "67890", "12345"],
    // };


    const [replyIds, setReplyIds] = useState<string[]>([]);
    const [threadOwnerUsername, setThreadOwnerUsername] = useState<string>('');

    useEffect(() => {
        getRepliesByThreadId(thread._id)
          .then(replies => {
              const ids = replies.map((reply: Reply) => reply._id);
              setReplyIds(ids);
          })
          .catch(error => {
            console.error('Error fetching replies:', error);
          });
      }, [thread._id]);

      //useEffect to get the username of the thread owner
        useEffect(() => {
            getUsernameById(thread.USER_ID)
            .then(username => {
                console.log("Thread owner username is: ", username)
                setThreadOwnerUsername(username);
            })
            .catch(error => {
                console.error('Error fetching username:', error);
            });
        }, [thread.USER_ID]);

  return (

    
    <div className="pt-6">
        <Link href={`/forum/${thread._id}`}>
        <div className="w-[350px] p-2 border border-green-500 rounded-md">
                <div className="flex items-center pb-2">

                    {replyIds.length > 0 ? 
                    <MdForum className="text-5xl text-black" /> :
                    <MdOutlineForum className="text-5xl text-black" />
                    }
                    
                    {/** Title and username */}
                    
                    
                    <div>
                        <p className="text-md font-bold pl-2">{thread.TITLE && thread.TITLE.length >27 ? `${thread.TITLE.substring(0,27)}...` : thread.TITLE}</p>
                        <p className="text-xs font-bold pl-2">Created by {threadOwnerUsername}</p>
                    </div>

                    {replyIds.length > 0 ? 
                    <IoChatbubble className="text-md text-black ml-auto" /> :
                    <IoChatbubble className="text-md text-gray-300 ml-auto" />
                    }
                    {/** Number of replies */}
                    
                    <p className="pl-1 text-sm font-bold">{replyIds.length.toString()}</p>
                    
                    
                </div>

                <div className="flex items-center justify-between">
                    {/** Date/Time and location */}
                    <p className='text-xs font-bold pl-2 pb-2'>| {thread.DATE_CREATED.substring(0,10)} | {thread.DATE_CREATED.substring(11,16)} |</p>
                    <p className='text-xs font-bold pl-2 pb-2 text-right'>{thread.LOCATION}</p>
                </div>
                

                {/** Body in a light grey background, with rounded corners */}
                <div className="bg-gray-100 p-2 rounded-md">
                    <p className="text-xs">{thread.BODY && thread.BODY.length > 120 ? `${thread.BODY.substring(0, 120)}...` : thread.BODY}</p>
                </div>
            </div>
        </Link>
    </div>
    
  )
}

export default ForumThread