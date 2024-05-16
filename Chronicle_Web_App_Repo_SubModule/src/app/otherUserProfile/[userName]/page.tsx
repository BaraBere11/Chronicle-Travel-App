"use client";

import React, { useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import CustomLayout from "@/components/CustomLayout";
import { getUserByUsername, getAllJournalEntriesById } from "@/lib/userData";
import { UserCircleIcon } from "@heroicons/react/solid";
import PostCard from "@/components/PostCard";
import { JournalEntry } from "@/store/UserSlice";
import fetchImage from "@/lib/attachments";
import Image from "next/image";
import TopNavBar from "@/components/TopNavBar";

type UserByNameProps = {
  params: {
    userName: string;
  };
};

const ProfilePage: React.FC<UserByNameProps> = ({ params }) => {
  const [imgSrc, setImgSrc] = useState('');
  const [userData, setUserData] = useState<any>(null);
  const [journalEntries, setJournalEntries] = useState<any[]>([]);
  const searchParams = useSearchParams();
  const userName = params.userName;
  const [imageId, setImageId] = useState('');
  
  

  console.log(userName);

  useEffect(() => {
    const fetchUserData = async () => {
      if (!userName) return;

      try {
        const userData = await getUserByUsername(userName);
        console.log(userData);
        setUserData(userData);
        setImageId(userData.PROFILE_IMAGE_ID);
        console.log(userData);
      } catch (error) {
        console.error("Error fetching user data:", error);
      }
    };

    fetchUserData();
  }, [userName]);

  useEffect(() => {
    const fetchJournalEntries = async () => {
      try {
        console.log(userData._id);

        const data = await getAllJournalEntriesById(userData._id);

        // Create a new array with only jounralEntries that are IS_PRIVATE === false
        const publicEntries = data.filter((entry: JournalEntry) => entry.IS_PRIVATE === false);

        setJournalEntries(publicEntries);
        console.log(publicEntries);
      } catch (error) {
        console.error("Error fetching journal entries:", error);
      }
    };

    if (userData && userData._id) {
      fetchJournalEntries();
    }
  }, [userData]);

  useEffect(() => {
    fetchImage(imageId)
      .then(setImgSrc)
      .catch(() => setImgSrc(''));
  }, [imageId]);

//fix 
  return (
    <CustomLayout showNavbar>
      <TopNavBar />
      <div className="container mx-auto">
        {userData ? (
          <div className="max-w-md mx-auto bg-white shadow-md rounded-md mt-12">
            {imgSrc ? (
                <div className='flex flex-col items-center pb-4'>

                  <Image
                      src={imgSrc}
                      alt="Dynamic from API"
                      //layout=" "
                      width={150}
                      height={150}
                      className="rounded-full object-cover border-2 border-green-500"
                    />
                {/* <img src={imgSrc} alt="Dynamic from API" className="h-36 w-36" /> */}
                </div>
              ) : (
                <div className='flex flex-col items-center'>
                <UserCircleIcon className="h-24 w-24" />
                </div>
              )}
            <div  className="flex flex-col items-center">
              <p className="text-2xl font-semibold mb-1 flex flex-col items-center">{`${userData.FIRST_NAME} ${userData.LAST_NAME}`}</p>
              <p className="text-gray-600 font-semibold">@{userData.USER_NAME}</p>
            </div>
          <br/>
            <div className="flex flex-col items-center">
              <p className="text-black font-semibold">Email</p>
              <p className="text-gray-900">{userData.EMAIL_ADDRESS}</p>
              <br/>
              <p className="text-black font-semibold">Chronicle Member Since</p>
              <p className="text-gray-900">{userData.DATE_CREATED.substring(0, 10)}</p>

            </div>
            {journalEntries.length > 0 && (
              <div className="mt-8">
                
                <h2 className="text-2xl font-bold flex flex-col items-center">T I M E L I N E</h2>
                <h2 className="text-2xl font-bold flex flex-col items-center">E N T R I E S</h2>

                <br/>
                {journalEntries.map((entry: any) => (
                  <PostCard key={entry._id} entry={entry}/>
                ))}
              </div>
            )}
          </div>
        ) : (
          <p className="text-center mt-12">Loading user data...</p>
        )}
      </div>
      <br />
      <br />
    </CustomLayout>
  );
};

export default ProfilePage;
