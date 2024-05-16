"use client";

import Image from "next/image";
import Link from "next/link";
import CustomLayout from "@/components/CustomLayout";
import { isAuthenticated } from "@/lib/authenticate";
import { useLayoutEffect } from "react";
import { RootState } from "@/store/store";
import { useDispatch, useSelector } from "react-redux";
import { useEffect, useState } from "react";
import { getJournalEntries, deleteJournalEntry, setJournalEntryPrivacy, removeUserFromLikes, addUserToLikes, getUserById } from "@/lib/userData";
import { JournalEntry, updateJournalEntryPrivacy, addUserToJournalEntryLikes, removeUserFromJournalEntryLikes } from "@/store/UserSlice";
import {useRouter, redirect, usePathname} from 'next/navigation';
import fetchImage from "@/lib/attachments";
import {MenuIcon, ThumbUpIcon as ThumbUpIconSolid} from '@heroicons/react/solid';
import {ThumbUpIcon as ThumbUpIconOutline} from '@heroicons/react/outline';
import SearchBar from "../../components/SearchBar";

const HomePage = () => {

// 
  {/* Authentication Check */}
  useLayoutEffect(() => {
    const isAuth = isAuthenticated();
    //console.log("Authentication check: ", isAuth);
    if (!isAuth) {
      redirect("/");
    }
  }, []);

  {/* Redux State*/}
  {/* ===========*/}
  const user = useSelector((state: RootState) => state.user);
  const dispatch = useDispatch();

  {/* Next Router */}
  const router = useRouter();
  const pathname = usePathname();

  {/* Page States */}
  {/* ===========*/}
  const [journalEntries, setJournalEntries] = useState<JournalEntry[]>([]);
  const [searchText, setSearchText] = useState("");
  const [showMenu, setShowMenu] = useState(false);

  const [menuVisibility, setMenuVisibility] = useState<{ [key: string]: boolean }>({});

  const [deleteConfirmation, setDeleteConfirmation] = useState(false);
  const [successMsg, setSuccessMsg] = useState('');
  const [imageIds, setImageIds] = useState<{ [key: string]: string }>({});
  const [profilePics, setProfilePics] = useState<{ [key: string]: string }>({});
  // Add a new state variable for the entry to delete
  const [entryToDelete, setEntryToDelete] = useState<JournalEntry | null>(null);
  
  // Add a new state variable for the entry to like
  const [entryToLike, setEntryToLike] = useState<JournalEntry | null>(null);
  

  {/* Page Effects */}

  {/* ============= */}
  

  {/* Page Functions */}
  {/* ============== */}

  {/* Retrieve Appropriate User Profile Link */}
  const getUserProfileLink = (entry: JournalEntry) => {
    return user.USER_NAME === entry.USER_NAME ? "/profile" : `/otherUserProfile/${entry.USER_NAME}`;
  };

  {/* Check if User is Owner of Journal Entry */}
   const ifUserIsOwner = (entry: JournalEntry) => {
    return user.USER_NAME === entry.USER_NAME;
  };

  {/* Handle Menu Click */}
  const handleMenu = (entryId: string) => {
    console.log("Menu Clicked")
    setMenuVisibility(prevState => ({
      ...prevState,
      [entryId]: !prevState[entryId]
    }));
  };

  {/* For Updating Privacy */}
  const handlePrivacy = async (entry: JournalEntry) => {
    console.log("Change Status Button Clicked");
    const privacy = !entry.IS_PRIVATE;
    try {
      if (entry && entry._id) {
        await setJournalEntryPrivacy(entry._id, privacy);
        dispatch(updateJournalEntryPrivacy({ entryId: entry._id, privacy }));
        console.log("Privacy updated");
        setSuccessMsg('Changed privacy setting to ' + (privacy ? 'Private' : 'Public'));  
        fetchAndSetPublicJournalEntries();
        // Set the menu visibility for the specific entry to false
        setMenuVisibility(prevState => ({
          ...prevState,
          [entry._id]: false
        }));

        console.log("Menu switch state: ", showMenu)
        setTimeout(() => {
          setSuccessMsg('');
        }, 2500);
        
      } else {
        console.error('Journal entry or journal entry ID is undefined');
      }
    } catch (error) {
      console.error('Failed to update journal entry privacy: ', error);
    }
  };

  {/* Refresh Home Page After Privacy Update */}
  useEffect(() => {
    if (successMsg === '') {
      router.refresh();
    }
  }, [successMsg, router]);

  {/* Retrieve Journal Entry Privacy */}
  const retrieveEntryPrivacy = (entry: JournalEntry) => {
    return entry.IS_PRIVATE ? 'Private' : 'Public';
  };



  {/* Fetch All Users Public Journal Entries */}

  const fetchAndSetPublicJournalEntries = async () => {
    //console.log("Fetching All Users Public Journal Entries");
    const entries = await getJournalEntries();
    //console.log("Fetched entries!")
    //console.log("Entries: ", entries)
    setJournalEntries(entries);
  };

  useEffect(() => {
    fetchAndSetPublicJournalEntries();
  }, []);

  const handleSearchChange = (text: string) => {
    setSearchText(text);
  };
  const filteredEntries = journalEntries.filter((entry) =>
    entry.TITLE.toLowerCase().includes(searchText.toLowerCase()) ||
    entry.BODY.toLowerCase().includes(searchText.toLowerCase())
  );

  {/* Fetch Image */}
  useEffect(() => {
    const fetchAndSetImageIds = async () => {
      const newImageIds: { [key: string]: string } = {};
      const newProfilePics: { [key: string]: string } = {};
  
  
      for (const entry of journalEntries) {
        console.log('==================== ATTACHMENT_ID: ================================ :', entry.ATTACHMENT_IDS[0])
        if (entry.ATTACHMENT_IDS[0] !== undefined) {
          const img = await fetchImage(entry.ATTACHMENT_IDS[0]);
          newImageIds[entry._id] = img;
        }

        if (entry.USER_ID) {
          let user = await getUserById(entry.USER_ID);
          console.log('==================== PROFILE IMAGE: ================================ :', user.PROFILE_IMAGE_ID)
          
          
          try {
            if (user.PROFILE_IMAGE_ID) {
              if (user.PROFILE_IMAGE_ID !== undefined) {
              let profile_pic = await fetchImage(user.PROFILE_IMAGE_ID);
              newProfilePics[entry._id] = profile_pic;
              }
            } else {
              let profile_pic = '/jonathan.jpg';
              newProfilePics[entry._id] = profile_pic;
              throw new Error("No profile image ID found for the user. Using placeholder image instead.");

            }
          } catch (error) {
            console.error(error);
          }
          
        }

      }
      //console.log('Profile Pics: ', newProfilePics)
      setImageIds(newImageIds);
      setProfilePics(newProfilePics);
    };
  
    fetchAndSetImageIds();
  }, [journalEntries]);

  {/* For Conditionally Displaying Delete Confirmation */}
  const showDeleteConfirmation = (entry: JournalEntry) => {
    setEntryToDelete(entry);
    console.log("Delete Confirmation Clicked");
    setDeleteConfirmation(true);
    setMenuVisibility(prevState => ({
      ...prevState,
      [entry._id]: false
    }));
  } 

  const hideDeleteConfirmation = (e: React.MouseEvent<HTMLButtonElement>) => {
    e.preventDefault();
    console.log("Delete Confirmation Cancelled");
    setDeleteConfirmation(false);
  }

    {/*Delete Journal Entry*/}
    // Update the handleDelete function to use the entryToDelete state variable
    const handleDelete = async () => {
      if (entryToDelete && entryToDelete._id) {
        try {
          await deleteJournalEntry(entryToDelete._id);
          setSuccessMsg('Journal entry deleted successfully');
          setDeleteConfirmation(false);
          setShowMenu(false);
          setTimeout(() => {
            setSuccessMsg('');
            setJournalEntries(journalEntries.filter(journalEntry => journalEntry._id !== entryToDelete._id));
          }, 2500);
        } catch (error) {
          console.error('Failed to delete journal entry: ', error);
        }
      }
    }

    {/* For Handling Like */}
    {/* entry is passed as argument */}
    const handleLike = async (entry:JournalEntry) => {
      console.log("Like Clicked");

      setEntryToLike(entry);
      console.log("Entry to like: ", entry);

      console.log("User: ", user._id);
    

      if (entry && entry._id) {
        {/* Check if User has liked the post */}
        {/*Check if the Users ID is in the the likes array*/
        if (entry.LIKES.includes(user._id)) {
          console.log("User has already liked this post");
          {/* Remove the Users ID from the likes array */}
          try {
            await removeUserFromLikes(entry._id, user._id);
            dispatch(removeUserFromJournalEntryLikes({ entryId: entry._id, userId: user._id }));
            console.log("User removed from likes array");
            fetchAndSetPublicJournalEntries();
            //if user._id is in the likes array
          } catch (error) {
            console.error('Failed to remove user from likes array: ', error);
          }
          
        } else {
          console.log("User has not liked this post");
          {/* Add the Users ID to the likes array */}
          try {
            await addUserToLikes(entry._id, user._id);
            dispatch(addUserToJournalEntryLikes({ entryId: entry._id, userId: user._id }));
            console.log("User added to likes array");
            fetchAndSetPublicJournalEntries();
            
          } catch (error) {
            console.error('Failed to add user to likes array: ', error);
          }
        }
      }
    }
  };

  return (
    <>
     <CustomLayout showNavbar>
      

     {/* Search Bar */}
     <SearchBar placeholder="Search in public entries..." onSearchChange={handleSearchChange} />
     {/* Page Title */}
     <div className="flex justify-center">

     
        <h1 className="text-3xl font-bold py-2 mt-2">Travel <span className='text-green-500'>Chronicles</span></h1>

      </div>

        {/* Render If No Journal Entries */}
        <div className="mb-16">
        {journalEntries.length === 0 && (
          <div className="flex justify-center pt-4">
            <h1 className="text-2xl font-semibold py-4 ml-2">No Timeline Entries</h1>
          </div>
            )}

          {/* Render Success Message */}
          {successMsg && (<div className="bg-green-500 text-white px-4 py-2 rounded-xl ml-4 mr-4">{successMsg}</div>)}

            {/* Render Journal Entries */}
            {filteredEntries.map((entry: JournalEntry) => (
            <div className="border-[2px] border-green-500 rounded m-4 flex flex-col relative" key={entry._id}>
              <div className="w-full max-w-full rounded overflow-hidden pt-2">
                <div className="flex items-center">
                  <Link href={getUserProfileLink(entry)} className="ml-2">
                      <div className="flex items-center">
                        <div className="w-16 h-16">

                        {profilePics[entry._id] ? (
                          <Image
                            src={profilePics[entry._id]}
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

                  {/* {ifUserIsOwner(entry) ? (
                    <MenuIcon className="h-8 w-8 cursor-pointer ml-auto mr-4 relative mb-4" onClick={handleMenu}/>
                  ) : null} */}

                  {ifUserIsOwner(entry) ? (
                      <MenuIcon className="h-8 w-8 cursor-pointer ml-auto mr-4 relative mb-4" onClick={() => handleMenu(entry._id)}/>
                    ) : null}

                   {/* If User is Owner, Render Hamburger Menu */}
                   {menuVisibility[entry._id] && ifUserIsOwner(entry) ?(
                    <div className="absolute right-0 top-0 mt-12 mr-4 bg-white border-[2px] border-dotted border-green-500 rounded p-2" style={{ zIndex: 99999 }}>
                      <Link href={`/journal/editJournalEntry/${entry._id}`}>
                        <p className="text-gray-700 text-sm font-bold py-1">Edit</p>
                      </Link>
                        <button className="text-gray-700 text-sm font-bold py-1" onClick={() => showDeleteConfirmation(entry)}>Delete</button>
                        <br/>  
                        <button className="text-gray-700 text-sm font-bold py-1" onClick={() => handlePrivacy(entry)}>Change Status</button>
                    </div>
                  ) : null}
                  </div>

                <div className='m-2'>
                <Link href={`/journal/${entry._id}`}>
                  <div className='border-green-500 border-[1px] rounded m-2'>
                  {imageIds[entry._id] && imageIds[entry._id].startsWith("https") ? (
                    <video width="500" height="300" controls>
                      <source src={imageIds[entry._id]} type={`video/${imageIds[entry._id]?.split('.').pop()?.split('?')[0]}`} />
                      Your browser does not support the video tag.
                    </video>
                  ) : (
                    <Image
                      className="w-full h-auto"
                      src={imageIds[entry._id]}
                      alt="Sunset in the mountains"
                      width={500}
                      height={300}
                    />
                  )}
                  </div>

                  <div className="px-2">
                      <div className="font-bold text-xl mb-2 flex justify-between items-center">{`${entry.TITLE}`}
                        <div className="flex items-center">
                          <div className={`h-3 w-3 rounded-full mr-1 ${entry.IS_PRIVATE ? 'bg-amber-500' : 'bg-green-500'}`}>
                              </div>
                              <p className="text-sm">{retrieveEntryPrivacy(entry)}</p>
                          </div>
                        </div>
                      </div>
                      </Link>

                      <div className="px-2 py-2">
                        <p className="text-gray-700 text-base pb-4">
                          {entry.BODY && entry.BODY.length > 40 ? `${entry.BODY.substring(0, 40)}...` : entry.BODY}
                          
                          <div className="flex items-center justify-between">
                            <p className="text-gray-500 text-sm font-bold pt-4 pr-10">{`${entry.LOCATION}`}</p>
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
                        </p>
                        <div className="flex justify-between items-center">
                          <p className="text-gray-500 text-sm font-bold">{`${entry.DATE.substring(0, 10)}`}</p>
                          
                        

                      

                          
                           
                          <div className="flex justify-end items-center">
                              <div className="pr-4 pt-2"> 
                                {/** Display the number of likes */}
                                {/* If the entry has likes, display the number of likes */}
                                {entry.LIKES.length > 0 ? (
                                  <div className="flex items-center">

                                    

                          

                                     
                                                        
                                    <p className="text-gray-500 text-sm font-bold">{`${entry.LIKES.length} ${entry.LIKES.length > 1 ? ' Likes' : ' Like'}`}</p>

                                  </div>
                                ) : null}
                              </div>
                          


                              {!ifUserIsOwner(entry) ? (
                                <div className="flex justify-end items-center">
                                  {entry.LIKES.includes(user._id) ? (
                                    <a onClick={()=>handleLike(entry)}>
                                    <ThumbUpIconSolid className="h-10 w-10 text-green-500"/>
                                  </a>
                                  
                                ): 
                                  <a onClick={()=>handleLike(entry)}>
                                  <ThumbUpIconOutline className="h-10 w-10 text-green-500"/>
                                  </a> }
                                
                                </div>
                                ) : null}
                          </div>

                        </div>
                  </div>
                
                </div>
            </div>

            {/* Delete Confirmation Window */}
            {deleteConfirmation &&
              <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full flex justify-center items-center z-10">
                <div className="bg-white p-5 rounded-lg shadow-xl">
                    <h2 className="text-lg font-semibold mb-4 text-center">Confirm Deletion</h2>
                    <p className="mb-4 justify-center text-center">Are you sure you want <br/> to delete this entry?</p>
                    <div className="flex justify-between">
                        <button onClick={hideDeleteConfirmation} className="bg-gray-300 text-gray-700 px-4 py-2 ml-5 rounded hover:bg-gray-400">No</button> 
                        <button onClick={() => handleDelete()} className="bg-red-500 text-white px-4 py-2 mr-5 rounded hover:bg-red-600">Yes</button>
                    </div>
                </div>
              </div>
            }
          </div>
          
          
          
            ))}
            </div>
           
    </CustomLayout>


    </>  
  );
};



export default HomePage;
