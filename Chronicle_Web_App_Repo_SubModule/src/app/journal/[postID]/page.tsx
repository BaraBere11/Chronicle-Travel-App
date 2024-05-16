'use client';
import React,{ useEffect, useState } from 'react'
import Link from 'next/link';
import Image from 'next/image'
import { getJournalEntryById } from '@/lib/userData';
import { JournalEntry, updateJournalEntryPrivacy } from "@/store/UserSlice";
import fetchImage from '@/lib/attachments';
import {MenuIcon} from '@heroicons/react/outline';
import { RootState } from '@/store/store';
import { useSelector, useDispatch} from 'react-redux';
import {deleteJournalEntry, setJournalEntryPrivacy, getUserById} from '@/lib/userData';
import {useRouter, redirect} from 'next/navigation';
import CustomLayout from '@/components/CustomLayout';
import TopNavBar from '@/components/TopNavBar';
import { MapContainer, Marker, TileLayer, Tooltip,Popup } from "react-leaflet"
import "leaflet/dist/leaflet.css"
import "leaflet-defaulticon-compatibility"
import "leaflet-defaulticon-compatibility/dist/leaflet-defaulticon-compatibility.css"
import LeafletMap from '@/components/LeafletMap';


type JournalPostByIDProps = {
  params: {
    postID: string;
  };
};

const JournalPostByID = ({ params }: JournalPostByIDProps) => {

  {/* Page States */}
  {/* ===========*/}
  const [journalEntry, setJournalEntry] = useState<JournalEntry>();
  const [imgSrc, setImgSrc] = useState('');
  const [showMenu, setShowMenu] = useState(false);
  const [deleteConfirmation, setDeleteConfirmation] = useState(false);
  const [successMsg, setSuccessMsg] = useState('');
  const [entryId, setEntryId] = useState<string>(params.postID);
  const [profilePicSrc, setProfilePicSrc] = useState('');

  {/* Redux State*/}
  {/* ===========*/}
  const user = useSelector((state: RootState) => state.user);
  const dispatch = useDispatch();

  {/* Next Router */}
  const router = useRouter();

  {/* Page Variables */}
  {/* ============== */}
  const imageId = journalEntry?.ATTACHMENT_IDS?.[0]
  const userProfileLink = journalEntry?.USER_NAME === user.USER_NAME ? "/profile" : `/otherUserProfile/${journalEntry?.USER_NAME}`;


  {/* Page Effects*/}
  {/* ============*/}

  {/* Fetch Journal Entry */}
  useEffect(() => {
    const fetchJournalEntry = async () => {
      const entry = await getJournalEntryById(entryId);
      setJournalEntry(entry);
    };
  
    fetchJournalEntry();
  }, [entryId]);
  

  {/* Fetch Image */}
  useEffect(() => {
    if (imageId) {
      fetchImage(imageId)
        .then(setImgSrc)
        .catch(() => {
          setImgSrc(''); // Consider setting a fallback image or displaying an error message
          console.error('Failed to fetch image');
        });
    }
  }, [imageId]);

  useEffect(() => {
    const fetchProfilePic = async () => {
      const entry = await getJournalEntryById(entryId);

      if (entry.USER_ID) {
        let user = await getUserById(entry.USER_ID);
        let profile_pic = await fetchImage(user.PROFILE_IMAGE_ID);
        setProfilePicSrc(profile_pic);
        }
      }
  
    fetchProfilePic();
  });

  {/* Display Menu State */}
  useEffect(() => {
    console.log("Show menu state: ", showMenu);
    console.log("Show delete confirmation state: ", deleteConfirmation);
  }, [showMenu, deleteConfirmation]);

  {/* Page Functions */}
  {/* ============== */}

  {/* For Conditionally Displaying Menu */}
  const handleMenu = () => {
    setShowMenu(!showMenu);
  }

  {/*Delete Journal Entry*/}
  const handleDelete = async () => {
    try {
      await deleteJournalEntry(entryId);
      console.log("Delete confirmed");
      //redirect to journal page
      router.replace('/journal');
    } catch (error) {
      console.error('Failed to delete journal entry: ', error);
    }
  }

  {/* For Conditionally Displaying Delete Confirmation */}
  const showDeleteConfirmation = (e: React.MouseEvent<HTMLButtonElement>) => {
    e.preventDefault();
    console.log("Delete confirmation clicked");
    setDeleteConfirmation(true);
  } 

  const hideDeleteConfirmation = (e: React.MouseEvent<HTMLButtonElement>) => {
    e.preventDefault();
    console.log("Delete confirmation clicked");
    setDeleteConfirmation(false);
  }

  {/* For Updating Privacy */}
  const handlePrivacy = async () => {
    console.log("Button clicked");
    const privacy = !journalEntry?.IS_PRIVATE;
    try {
      if (journalEntry && journalEntry._id) {
        await setJournalEntryPrivacy(journalEntry._id, privacy);
        dispatch(updateJournalEntryPrivacy({ entryId: journalEntry?._id, privacy }));
        console.log("Privacy updated");
        setSuccessMsg('Changed privacy setting to ' + (privacy ? 'Private' : 'Public'));  
        console.log("Redirecting to journal page");
        setShowMenu(!showMenu);
        setTimeout(() => {
          router.replace('/journal');
        }, 2500);
       
      } else {
        console.error('Journal entry or journal entry ID is undefined');
      }
    } catch (error) {
      console.error('Failed to update journal entry privacy: ', error);
    }
  }
  console.log("Location Rating: ", journalEntry?.LATITUDE)
  console.log("Location Rating: ", journalEntry?.LONGITUDE)
  return (
    <>
      <CustomLayout showNavbar>
       <TopNavBar />
        {successMsg && (<div className="bg-green-500 text-white px-4 py-2 rounded-xl ml-4 mr-4">{successMsg}</div>)}
            <div className="border-[2px] border-green-500 rounded m-4 flex flex-col relative">
              <div className="w-full max-w-full rounded overflow-hidden pt-2">
                <div className="flex items-center">
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
                            <p className="text-gray-900 text-sm leading-none px-3">{`${journalEntry?.FULL_NAME}`}</p>
                            <p className="text-gray-500 text-sm font-bold px-3">{`@${journalEntry?.USER_NAME}`}</p>
                        </div>
                    </div>
                  </Link>

                    {journalEntry?.USER_NAME === user.USER_NAME ? (
                    <MenuIcon className="h-8 w-8 cursor-pointer ml-auto mr-4 relative mb-4" onClick={handleMenu}/>
                  ) : null}

                  {/* POST MENU*/}
                  {showMenu && journalEntry?.USER_NAME === user.USER_NAME ?(
                    <div className="absolute right-0 top-0 mt-12 mr-4 bg-white border-[2px] border-dotted border-green-500 rounded p-2" style={{ zIndex: 99999 }}>
                      <Link href={`/journal/editJournalEntry/${journalEntry?._id}`}>
                        <p className="text-gray-700 text-sm font-bold py-1">Edit</p>
                      </Link>
                      {/* Juan: this handles display of delete confirmation window*/}
                        <button className="text-gray-700 text-sm font-bold py-1" onClick={showDeleteConfirmation}>Delete</button>
                        <br/>  
                        <button className="text-gray-700 text-sm font-bold py-1" onClick={handlePrivacy}>Change Status</button>
                    </div>
                  ) : null}
                </div>
                <div className='border-green-500 border-2 rounded m-2'>
                {imgSrc && imgSrc.startsWith("https") ? (
                  <video width="500" height="300" controls>
                    {imgSrc && (
                      <source src={imgSrc} type={`video/${imgSrc.split('.').pop()?.split('?')[0]}`} />
                    )}
                    Your browser does not support the video tag.
                  </video>
                ) : (
                  <Image
                    className="w-full h-auto"
                    src={imgSrc ?? ""}
                    alt="Sunset in the mountains"
                    width={500}
                    height={300}
                  />
                )}
                </div>
                <div className="px-2 py-2">


                <div className="flex justify-between items-center">
                  <div className="font-bold text-xl mb-2">
                      {`${journalEntry?.TITLE}`}
                    </div>
                      <div className="flex justify-end items-center pb-2">
                        <div className={`h-3 w-3 rounded-full ${journalEntry?.IS_PRIVATE ? 'bg-amber-500' : 'bg-green-500'} mr-1`}></div>
                        <p className = "text-sm font-bold">{journalEntry?.IS_PRIVATE ? 'Private' : 'Public'}</p>
                      </div>
                    </div>



                        <p className="text-gray-700 text-base pb-4">
                          {journalEntry?.BODY} 
                        </p>

                        <div className="flex justify-between items-center pb-2"> 
                          <p className="text-gray-500 text-sm font-bold py-1 pr-10">{`${journalEntry?.LOCATION}`}</p>
                          <div className="flex items-center">
                            {journalEntry && journalEntry.LOCATION_RATING > 0 ?
                            <svg className="w-2 h-2 text-yellow-300 ms-1" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 22 20">
                            <path d="M20.924 7.625a1.523 1.523 0 0 0-1.238-1.044l-5.051-.734-2.259-4.577a1.534 1.534 0 0 0-2.752 0L7.365 5.847l-5.051.734A1.535 1.535 0 0 0 1.463 9.2l3.656 3.563-.863 5.031a1.532 1.532 0 0 0 2.226 1.616L11 17.033l4.518 2.375a1.534 1.534 0 0 0 2.226-1.617l-.863-5.03L20.537 9.2a1.523 1.523 0 0 0 .387-1.575Z"/>
                            </svg>
                            :
                            <svg className="w-2 h-2 ms-1 text-gray-300 dark:text-gray-500" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 22 20">
                              <path d="M20.924 7.625a1.523 1.523 0 0 0-1.238-1.044l-5.051-.734-2.259-4.577a1.534 1.534 0 0 0-2.752 0L7.365 5.847l-5.051.734A1.535 1.535 0 0 0 1.463 9.2l3.656 3.563-.863 5.031a1.532 1.532 0 0 0 2.226 1.616L11 17.033l4.518 2.375a1.534 1.534 0 0 0 2.226-1.617l-.863-5.03L20.537 9.2a1.523 1.523 0 0 0 .387-1.575Z"/>
                              </svg>
                              }
                            {journalEntry && journalEntry.LOCATION_RATING > 1 ?  
                            <svg className="w-2 h-2 text-yellow-300 ms-1" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 22 20">
                                <path d="M20.924 7.625a1.523 1.523 0 0 0-1.238-1.044l-5.051-.734-2.259-4.577a1.534 1.534 0 0 0-2.752 0L7.365 5.847l-5.051.734A1.535 1.535 0 0 0 1.463 9.2l3.656 3.563-.863 5.031a1.532 1.532 0 0 0 2.226 1.616L11 17.033l4.518 2.375a1.534 1.534 0 0 0 2.226-1.617l-.863-5.03L20.537 9.2a1.523 1.523 0 0 0 .387-1.575Z"/>
                            </svg>
                            :
                            <svg className="w-2 h-2 ms-1 text-gray-300 dark:text-gray-500" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 22 20">
                                <path d="M20.924 7.625a1.523 1.523 0 0 0-1.238-1.044l-5.051-.734-2.259-4.577a1.534 1.534 0 0 0-2.752 0L7.365 5.847l-5.051.734A1.535 1.535 0 0 0 1.463 9.2l3.656 3.563-.863 5.031a1.532 1.532 0 0 0 2.226 1.616L11 17.033l4.518 2.375a1.534 1.534 0 0 0 2.226-1.617l-.863-5.03L20.537 9.2a1.523 1.523 0 0 0 .387-1.575Z"/>
                            </svg>
                            }
                            {journalEntry && journalEntry.LOCATION_RATING > 2 ?  
                            <svg className="w-2 h-2 text-yellow-300 ms-1" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 22 20">
                                <path d="M20.924 7.625a1.523 1.523 0 0 0-1.238-1.044l-5.051-.734-2.259-4.577a1.534 1.534 0 0 0-2.752 0L7.365 5.847l-5.051.734A1.535 1.535 0 0 0 1.463 9.2l3.656 3.563-.863 5.031a1.532 1.532 0 0 0 2.226 1.616L11 17.033l4.518 2.375a1.534 1.534 0 0 0 2.226-1.617l-.863-5.03L20.537 9.2a1.523 1.523 0 0 0 .387-1.575Z"/>
                            </svg>
                            :
                            <svg className="w-2 h-2 ms-1 text-gray-300 dark:text-gray-500" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 22 20">
                                <path d="M20.924 7.625a1.523 1.523 0 0 0-1.238-1.044l-5.051-.734-2.259-4.577a1.534 1.534 0 0 0-2.752 0L7.365 5.847l-5.051.734A1.535 1.535 0 0 0 1.463 9.2l3.656 3.563-.863 5.031a1.532 1.532 0 0 0 2.226 1.616L11 17.033l4.518 2.375a1.534 1.534 0 0 0 2.226-1.617l-.863-5.03L20.537 9.2a1.523 1.523 0 0 0 .387-1.575Z"/>
                            </svg>
                            }
                            {journalEntry && journalEntry.LOCATION_RATING > 3 ?  
                            <svg className="w-2 h-2 text-yellow-300 ms-1" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 22 20">
                                <path d="M20.924 7.625a1.523 1.523 0 0 0-1.238-1.044l-5.051-.734-2.259-4.577a1.534 1.534 0 0 0-2.752 0L7.365 5.847l-5.051.734A1.535 1.535 0 0 0 1.463 9.2l3.656 3.563-.863 5.031a1.532 1.532 0 0 0 2.226 1.616L11 17.033l4.518 2.375a1.534 1.534 0 0 0 2.226-1.617l-.863-5.03L20.537 9.2a1.523 1.523 0 0 0 .387-1.575Z"/>
                            </svg>
                            :
                            <svg className="w-2 h-2 ms-1 text-gray-300 dark:text-gray-500" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 22 20">
                                <path d="M20.924 7.625a1.523 1.523 0 0 0-1.238-1.044l-5.051-.734-2.259-4.577a1.534 1.534 0 0 0-2.752 0L7.365 5.847l-5.051.734A1.535 1.535 0 0 0 1.463 9.2l3.656 3.563-.863 5.031a1.532 1.532 0 0 0 2.226 1.616L11 17.033l4.518 2.375a1.534 1.534 0 0 0 2.226-1.617l-.863-5.03L20.537 9.2a1.523 1.523 0 0 0 .387-1.575Z"/>
                            </svg>
                            }
                            {journalEntry && journalEntry.LOCATION_RATING > 4 ?  
                            <svg className="w-2 h-2 text-yellow-300 ms-1" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 22 20">
                                <path d="M20.924 7.625a1.523 1.523 0 0 0-1.238-1.044l-5.051-.734-2.259-4.577a1.534 1.534 0 0 0-2.752 0L7.365 5.847l-5.051.734A1.535 1.535 0 0 0 1.463 9.2l3.656 3.563-.863 5.031a1.532 1.532 0 0 0 2.226 1.616L11 17.033l4.518 2.375a1.534 1.534 0 0 0 2.226-1.617l-.863-5.03L20.537 9.2a1.523 1.523 0 0 0 .387-1.575Z"/>
                            </svg>
                            :
                            <svg className="w-2 h-2 ms-1 text-gray-300 dark:text-gray-500" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 22 20">
                                <path d="M20.924 7.625a1.523 1.523 0 0 0-1.238-1.044l-5.051-.734-2.259-4.577a1.534 1.534 0 0 0-2.752 0L7.365 5.847l-5.051.734A1.535 1.535 0 0 0 1.463 9.2l3.656 3.563-.863 5.031a1.532 1.532 0 0 0 2.226 1.616L11 17.033l4.518 2.375a1.534 1.534 0 0 0 2.226-1.617l-.863-5.03L20.537 9.2a1.523 1.523 0 0 0 .387-1.575Z"/>
                            </svg>
                            }
                          </div>
                        </div>

                        <div className="flex justify-between items-center">
                        <p className="text-gray-500 text-sm font-bold py-1">{`${journalEntry?.DATE.substring(0, 10)}`}</p>
                        
                        





                        {/* Display Number of Likes in JournalEntry Likes Array*/}
                        {/** If Only 1 Like, display "Like", if more than 1 Like display "Likes"*/}
                        <p className="text-gray-500 text-sm font-bold py-1">{`${journalEntry?.LIKES.length} ${journalEntry?.LIKES.length === 1 ? 'Like' : 'Likes'}`}</p>
                         
                        

                </div>
                </div>
              </div>

                   {/* MAPS */}

              <div className="map-container" style={{ position: 'relative', height: '300px', width: '95%', margin: '0 auto' }}>
            {journalEntry?.LATITUDE && journalEntry?.LONGITUDE && (
              <LeafletMap latitude={journalEntry.LATITUDE} longitude={journalEntry.LONGITUDE} />
            )}
          </div>
               
<br />
           

            </div>
            {deleteConfirmation &&
              <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full flex justify-center items-center z-10">
                <div className="bg-white p-5 rounded-lg shadow-xl">
                    <h2 className="text-lg font-semibold mb-4 text-center">Confirm Deletion</h2>
                    <p className="mb-4 justify-center text-center">Are you sure you want <br/> to delete this entry?</p>
                    <div className="flex justify-between">
                        <button onClick={hideDeleteConfirmation} className="bg-gray-300 text-gray-700 px-4 py-2 ml-5 rounded hover:bg-gray-400">No</button> 
                        <button onClick={handleDelete} className="bg-red-500 text-white px-4 py-2 mr-5 rounded hover:bg-red-600">Yes</button>
                    </div>
                </div>
              </div>
            }
            
<br />
<br />

      </CustomLayout>
    </>
  )
}

export default JournalPostByID