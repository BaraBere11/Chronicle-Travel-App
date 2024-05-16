'use client';
import React from 'react'
import Image from 'next/image'
import {JournalEntry, updateJournalEntryPrivacy} from '@/store/UserSlice';
import Link from 'next/link';
import {MenuIcon} from '@heroicons/react/outline';
import {useState, useEffect} from 'react';
import { RootState } from '@/store/store';
import { useSelector, useDispatch} from 'react-redux';
import fetchImage from '@/lib/attachments';
import DeleteJournalEntryConfirmation from './DeleteJournalEntryConfirmation';
import {getUserById, setJournalEntryPrivacy} from '@/lib/userData';


interface PostProps {
  entry: JournalEntry;
}

const PostCard: React.FC<PostProps> = ({entry}) => {

  const dispatch = useDispatch();
  const [imgSrc, setImgSrc] = useState('');
  const imageId = entry.ATTACHMENT_IDS[0]
  const [addSuccess, setAddSuccess] = useState('');
  const [profilePicSrc, setProfilePicSrc] = useState('');
  const [showMenu, setShowMenu] = useState(false);
  const user = useSelector((state: RootState) => state.user);
  const [showDeleteConfirmation, setShowDeleteConfirmation] = useState(false);
  const userProfileLink = entry.USER_NAME === user.USER_NAME ? "/profile" : `/otherUserProfile/${entry.USER_NAME}`;
  const [menuVisibility, setMenuVisibility] = useState<{ [key: string]: boolean }>({});
  const [deleteConfirmation, setDeleteConfirmation] = useState(false);
  const [entryToDelete, setEntryToDelete] = useState<JournalEntry | null>(null);

  useEffect(() => {
    fetchImage(imageId)
      .then(setImgSrc)
      .catch(() => setImgSrc(''));
  }, [imageId]);

  useEffect(() => {
    const fetchProfilePic = async () => {

      if (entry.USER_ID) {
        let user = await getUserById(entry.USER_ID);
        let profile_pic = await fetchImage(user.PROFILE_IMAGE_ID);
        setProfilePicSrc(profile_pic);
        }
      }
  
    fetchProfilePic();
  });

  return (
    <>
    {addSuccess && (
        <div className="bg-green-500 text-white px-4 py-2 rounded-xl ml-4 mr-4">
          {addSuccess}
        </div>
      )}
      <div className="mb-8">
      <div className="border-[2px] border-green-500 rounded m-4 flex flex-col relative">
        <div className="w-full max-w-full rounded overflow-hidden pt-2">
        <div className="flex items-center">

            {/* <Link href={{pathname: `/otherUserProfile/${entry.USER_NAME}`}} className="ml-2"> */}
            <Link href={userProfileLink} className="ml-2">
              <div className="flex items-center">
                <div className="w-16 h-16">
                {profilePicSrc ? (
                          <Image
                            src={profilePicSrc}
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
                  <div>
                      <p className="text-gray-900 text-sm leading-none px-3">{`${entry.FULL_NAME}`}</p>
                      <p className="text-gray-500 text-sm font-bold px-3">{`@${entry.USER_NAME}`}</p>
                  </div>
              </div>
            </Link>
        </div>


        
        <Link href={`/journal/${entry._id}`}>
          <div className='border-green-500 border-[1px] rounded m-2'>
                {/* Juan: this conditionally renders delete confirmation window*/}
            {showDeleteConfirmation ? <DeleteJournalEntryConfirmation showDeleteConfirmation={true} entryId={entry._id}/> : null}
          {imgSrc && imgSrc.startsWith("https") ? (
                      <video width="500" height="300" controls>
                        <source src={imgSrc} type={`video/${imgSrc.split('.').pop()?.split('?')[0] || 'mp4'}`} />
                        Your browser does not support the video tag.
                      </video>
                  ) : (
                    <Image
                        className="w-full h-auto"
                        src={imgSrc}
                        alt="Sunset in the mountains"
                        width={500}
                        height={300}
                      />
                  )}
          
          </div>



          <div className="px-2 py-2">

          <div className="flex justify-between items-center">
                  <div className="font-bold text-xl mb-2">
                      {`${entry.TITLE}`}
                    </div>
                      <div className="flex justify-end items-center pb-2">
                        <div className={`h-3 w-3 rounded-full ${entry.IS_PRIVATE ? 'bg-amber-500' : 'bg-green-500'} mr-1`}></div>
                        <p className = "text-sm font-bold">{entry.IS_PRIVATE ? 'Private' : 'Public'}</p>
                      </div>
                    </div>
              
              <p className="text-gray-700 text-base pb-4">
                {entry.BODY && entry.BODY.length > 40 ? `${entry.BODY.substring(0, 40)}...` : entry.BODY}
              </p>
              <div className="flex justify-between items-center pb-2">            
                <p className="text-gray-500 text-sm font-bold py-1 pr-10">{`${entry.LOCATION}`}</p>

                <div className="flex items-center pt-2">
                          {/* If locationRating is 0, the star will be gray, otherwise it will be yellow*/}

                          {entry && entry.LOCATION_RATING > 0 ?
                          <svg className="w-3 h-3 text-yellow-300 ms-1" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 22 20">
                            <path d="M20.924 7.625a1.523 1.523 0 0 0-1.238-1.044l-5.051-.734-2.259-4.577a1.534 1.534 0 0 0-2.752 0L7.365 5.847l-5.051.734A1.535 1.535 0 0 0 1.463 9.2l3.656 3.563-.863 5.031a1.532 1.532 0 0 0 2.226 1.616L11 17.033l4.518 2.375a1.534 1.534 0 0 0 2.226-1.617l-.863-5.03L20.537 9.2a1.523 1.523 0 0 0 .387-1.575Z"/>
                          </svg>
                          :
                          <svg className="w-3 h-3ms-1 text-gray-300 dark:text-gray-500" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 22 20">
                            <path d="M20.924 7.625a1.523 1.523 0 0 0-1.238-1.044l-5.051-.734-2.259-4.577a1.534 1.534 0 0 0-2.752 0L7.365 5.847l-5.051.734A1.535 1.535 0 0 0 1.463 9.2l3.656 3.563-.863 5.031a1.532 1.532 0 0 0 2.226 1.616L11 17.033l4.518 2.375a1.534 1.534 0 0 0 2.226-1.617l-.863-5.03L20.537 9.2a1.523 1.523 0 0 0 .387-1.575Z"/>
                          </svg>
                            }
                          {entry && entry.LOCATION_RATING > 1 ?  
                          <svg className="w-3 h-3 text-yellow-300 ms-1" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 22 20">
                              <path d="M20.924 7.625a1.523 1.523 0 0 0-1.238-1.044l-5.051-.734-2.259-4.577a1.534 1.534 0 0 0-2.752 0L7.365 5.847l-5.051.734A1.535 1.535 0 0 0 1.463 9.2l3.656 3.563-.863 5.031a1.532 1.532 0 0 0 2.226 1.616L11 17.033l4.518 2.375a1.534 1.534 0 0 0 2.226-1.617l-.863-5.03L20.537 9.2a1.523 1.523 0 0 0 .387-1.575Z"/>
                          </svg>
                          :
                          <svg className="w-3 h-3 ms-1 text-gray-300 dark:text-gray-500" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 22 20">
                              <path d="M20.924 7.625a1.523 1.523 0 0 0-1.238-1.044l-5.051-.734-2.259-4.577a1.534 1.534 0 0 0-2.752 0L7.365 5.847l-5.051.734A1.535 1.535 0 0 0 1.463 9.2l3.656 3.563-.863 5.031a1.532 1.532 0 0 0 2.226 1.616L11 17.033l4.518 2.375a1.534 1.534 0 0 0 2.226-1.617l-.863-5.03L20.537 9.2a1.523 1.523 0 0 0 .387-1.575Z"/>
                          </svg>
                          }
                          {entry && entry.LOCATION_RATING > 2 ?  
                          <svg className="w-3 h-3 text-yellow-300 ms-1" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 22 20">
                              <path d="M20.924 7.625a1.523 1.523 0 0 0-1.238-1.044l-5.051-.734-2.259-4.577a1.534 1.534 0 0 0-2.752 0L7.365 5.847l-5.051.734A1.535 1.535 0 0 0 1.463 9.2l3.656 3.563-.863 5.031a1.532 1.532 0 0 0 2.226 1.616L11 17.033l4.518 2.375a1.534 1.534 0 0 0 2.226-1.617l-.863-5.03L20.537 9.2a1.523 1.523 0 0 0 .387-1.575Z"/>
                          </svg>
                          :
                          <svg className="w-3 h-3 ms-1 text-gray-300 dark:text-gray-500" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 22 20">
                              <path d="M20.924 7.625a1.523 1.523 0 0 0-1.238-1.044l-5.051-.734-2.259-4.577a1.534 1.534 0 0 0-2.752 0L7.365 5.847l-5.051.734A1.535 1.535 0 0 0 1.463 9.2l3.656 3.563-.863 5.031a1.532 1.532 0 0 0 2.226 1.616L11 17.033l4.518 2.375a1.534 1.534 0 0 0 2.226-1.617l-.863-5.03L20.537 9.2a1.523 1.523 0 0 0 .387-1.575Z"/>
                          </svg>
                          }
                          {entry && entry.LOCATION_RATING > 3 ?  
                          <svg className="w-3 h-3 text-yellow-300 ms-1" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 22 20">
                              <path d="M20.924 7.625a1.523 1.523 0 0 0-1.238-1.044l-5.051-.734-2.259-4.577a1.534 1.534 0 0 0-2.752 0L7.365 5.847l-5.051.734A1.535 1.535 0 0 0 1.463 9.2l3.656 3.563-.863 5.031a1.532 1.532 0 0 0 2.226 1.616L11 17.033l4.518 2.375a1.534 1.534 0 0 0 2.226-1.617l-.863-5.03L20.537 9.2a1.523 1.523 0 0 0 .387-1.575Z"/>
                          </svg>
                          :
                          <svg className="w-3 h-3 ms-1 text-gray-300 dark:text-gray-500" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 22 20">
                              <path d="M20.924 7.625a1.523 1.523 0 0 0-1.238-1.044l-5.051-.734-2.259-4.577a1.534 1.534 0 0 0-2.752 0L7.365 5.847l-5.051.734A1.535 1.535 0 0 0 1.463 9.2l3.656 3.563-.863 5.031a1.532 1.532 0 0 0 2.226 1.616L11 17.033l4.518 2.375a1.534 1.534 0 0 0 2.226-1.617l-.863-5.03L20.537 9.2a1.523 1.523 0 0 0 .387-1.575Z"/>
                          </svg>
                          }
                          {entry && entry.LOCATION_RATING > 4 ?  
                          <svg className="w-3 h-3 text-yellow-300 ms-1" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 22 20">
                              <path d="M20.924 7.625a1.523 1.523 0 0 0-1.238-1.044l-5.051-.734-2.259-4.577a1.534 1.534 0 0 0-2.752 0L7.365 5.847l-5.051.734A1.535 1.535 0 0 0 1.463 9.2l3.656 3.563-.863 5.031a1.532 1.532 0 0 0 2.226 1.616L11 17.033l4.518 2.375a1.534 1.534 0 0 0 2.226-1.617l-.863-5.03L20.537 9.2a1.523 1.523 0 0 0 .387-1.575Z"/>
                          </svg>
                          :
                          <svg className="w-3 h-3 ms-1 text-gray-300 dark:text-gray-500" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 22 20">
                              <path d="M20.924 7.625a1.523 1.523 0 0 0-1.238-1.044l-5.051-.734-2.259-4.577a1.534 1.534 0 0 0-2.752 0L7.365 5.847l-5.051.734A1.535 1.535 0 0 0 1.463 9.2l3.656 3.563-.863 5.031a1.532 1.532 0 0 0 2.226 1.616L11 17.033l4.518 2.375a1.534 1.534 0 0 0 2.226-1.617l-.863-5.03L20.537 9.2a1.523 1.523 0 0 0 .387-1.575Z"/>
                          </svg>
                          }
                      </div>



              </div>
                  <div className="flex justify-between items-center">
                    
                    <p className="text-gray-500 text-sm font-bold py-1">{`${entry.DATE.substring(0, 10)}`}</p>
                  <div className="flex justify-end items-center">
                  <p className="text-gray-500 text-sm font-bold py-1">{`${entry.LIKES.length} ${entry.LIKES.length === 1 ? 'Like' : 'Likes'}`}</p>
            </div>
          </div>

          </div>
          </Link>
        </div>

      </div>
      </div>

    </>
  )
}

export default PostCard