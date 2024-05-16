'use client'
import React, { useState, useEffect } from 'react';
import Link from 'next/link'; 
import CustomLayout from '@/components/CustomLayout';
import { CogIcon, UserCircleIcon } from '@heroicons/react/outline';
import { getAllJournalEntriesById } from '@/lib/userData';
import PostCard from '@/components/PostCard';
import { RootState } from '@/store/store';
import { useSelector } from 'react-redux';
import InfiniteScroll from 'react-infinite-scroll-component';
import dynamic from 'next/dynamic';


import fetchImage from '../../lib/attachments';
import Image from 'next/image';
import TopNavBar from '@/components/TopNavBar';

const UserInfoHeader = dynamic(() => import('@/app/profile/components/UserInfoHeader'), {
  ssr: false,
});

const ProfilePage = () => {
  const [imgSrc, setImgSrc] = useState('');
  const user = useSelector((state: RootState) => state.user);
  console.log('Profile Page Log: ', user);

  const [journalEntries, setJournalEntries] = useState<any[]>([]);

  let imageId: string;

  try {
    if (user.PROFILE_IMAGE_ID) {
      imageId = user.PROFILE_IMAGE_ID;
    } else {
      throw new Error("No profile image ID found for the user.");
    }
  } catch (error) {
    console.error(error);
    imageId = '/jonathan.jpg';
}

  useEffect(() => {
    const fetchJournalEntries = async () => {
      try {
        console.log(user._id);
        const data = await getAllJournalEntriesById(user._id);
        setJournalEntries(data);
        console.log(data);
      } catch (error) {
        console.error('Error fetching journal entries:', error);
      }
    };

    fetchJournalEntries();
  }, [user._id]); 

useEffect(() => {
    fetchImage(imageId)
      .then(setImgSrc)
      .catch(() => setImgSrc(''));
  }, [imageId]);
  
  return (
    <CustomLayout showNavbar>
      <TopNavBar />

      <div className='flex flex-col min-h-screen py-2 pt-0'>
        <div className="flex flex-col items-left justify-left min-h-screen py-4 pt-2">
          <div className="flex items-center justify-between pr-8">
            <div className="flex items-center">
              <h1 className='text-3xl font-semibold pl-8'>Profile</h1>
            </div>
            <Link href="/profile/settings">
              <CogIcon className="h-11 w-11" />
            </Link>

          </div>
          <br />
          <div className="flex items-center justify-center">
            <div className="flex flex-col items-center">
            {imgSrc ? (
                <div className='flex flex-col items-center pb-4'>

                {/* <img src={imgSrc} alt="Dynamic from API" className="h-36 w-36" /> */}
                <Image
                      src={imgSrc}
                      alt="Dynamic from API"
                      //layout=" "
                      width={150}
                      height={150}
                      className="rounded-full object-cover border-2 border-green-500"
                    />
                </div>
              ) : (
                <div className='flex flex-col items-center'>
                <UserCircleIcon className="h-24 w-24" />
                </div>
              )}
              <UserInfoHeader />
            </div>
          </div>
          {journalEntries.length === 0 ? (
            <div className="flex items-center justify-center">
              <h1 className="text-2xl font-semibold py-4 ml-2">No Entries</h1>
            </div>
          ) : (
            <InfiniteScroll
              dataLength={journalEntries.length}
              next={() => console.log("Next")}
              hasMore={true}
              loader={<h4 className="text-center">Loading...</h4>}
            >
              <br/><br/>
              <h2 className="text-2xl font-semibold flex flex-col items-center">A L L</h2>
              <h2 className="text-2xl mb-4 font-semibold flex flex-col items-center">E N T R I E S</h2>
              {journalEntries.map((entry, index) => (
                <PostCard key={index} entry={entry}/>
              ))}
            </InfiniteScroll>
          )}
        </div>
      </div>
    </CustomLayout>
  );
};

export default ProfilePage;