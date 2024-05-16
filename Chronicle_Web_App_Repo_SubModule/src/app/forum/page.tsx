"use client";
import React, { useEffect, useState } from 'react';
import CustomLayout from "@/components/CustomLayout";
import Image from "next/image";
import ForumThread from "@/components/ForumThread";
import { useRouter } from 'next/navigation';
import { getAllThreads } from '@/lib/userData';
import SearchBar from "@/components/SearchBar";

interface Thread {
  _id: string;
  TITLE: string;
  BODY: string;
  USER_ID: string;
  DATE_CREATED: string;
  ATTACHMENT_IDS: string[];
}

const ForumPage = () => {
  const [threads, setThreads] = useState<Thread[]>();
  const [filteredThreads, setFilteredThreads] = useState<Thread[]>([]);
  const router = useRouter();

  useEffect(() => {
    const fetchThreads = async () => {
      try {
        const fetchedThreads = await getAllThreads();
        console.log(fetchedThreads);
        setThreads(fetchedThreads);
        setFilteredThreads(fetchedThreads);
      } catch (error) {
        console.error("Failed to fetch threads:", error);
      }
    };

    fetchThreads();
  }, []);

  const handleCreateThreadClick = () => {
    router.push('/forum/addNewThread');
  };

  //Create search functionality for the forum page
  const handleSearchChange = (text: string) => {
    if (threads) {
      const filtered = threads.filter(thread =>
        thread.TITLE.toLowerCase().includes(text.toLowerCase()) ||
        thread.BODY.toLowerCase().includes(text.toLowerCase())
      );
      setFilteredThreads(filtered);
    }
  };
  
  return (
    <>
      <CustomLayout showNavbar>
      <SearchBar placeholder="Search threads..." onSearchChange={handleSearchChange} />
      <div className="flex flex-col items-center sticky top-4 z-10 bg-white">
        
                
          <h1 className="text-3xl font-bold py-2 mt-2">Message <span className='text-green-500'>Forum</span></h1> 
            
              <button
                className="bg-green-600 hover:bg-green-500 text-white font-bold py-2 px-4 rounded-2xl mt-4"
                onClick={handleCreateThreadClick}
              >
                Create New Thread
              </button>
          </div>
        <div className="mb-16">
          <div className="flex flex-col items-center">
              <div className="flex flex-col items-center mt-15 ml-2 mr-2 overflow-auto" style={{ maxHeight: 'calc(100vh - 50px)' }}>
                
              {filteredThreads.map((thread) => (
                <ForumThread key={thread._id} thread={{ ...thread, LOCATION: '' }} />
              ))}
            </div>
          </div>
        </div>
      </CustomLayout>
    </>
  );
};

export default ForumPage;
