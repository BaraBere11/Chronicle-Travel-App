'use client';
import React from 'react'
import Link from 'next/link';
import Image from 'next/image'
import { getJournalEntryById } from '@/lib/userData';
import { useEffect, useState } from "react";
import { JournalEntry, updateJournalEntryPrivacy } from "@/store/UserSlice";
import fetchImage from '@/lib/attachments';
import {MenuIcon} from '@heroicons/react/outline';
import { RootState } from '@/store/store';
import { useSelector, useDispatch} from 'react-redux';
import {deleteJournalEntry, setJournalEntryPrivacy} from '@/lib/userData';
import {useRouter} from 'next/navigation';



type DetailedPostProps = {
  entryID: string;
};


const DetailedPost: React.FC<DetailedPostProps> = ({ entryID }) =>  {

  {/* Page States */}
  {/* ===========*/}
  const [journalEntry, setJournalEntry] = useState<JournalEntry>();
  const [imgSrc, setImgSrc] = useState('');
  const [showMenu, setShowMenu] = useState(false);
  const [deleteConfirmation, setDeleteConfirmation] = useState(false);
  const [addSuccess, setAddSuccess] = useState('');

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
      const entry = await getJournalEntryById(entryID);
      setJournalEntry(entry);
    };

    fetchJournalEntry();
  }, [entryID]);

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
    await deleteJournalEntry(entryID);
    console.log("Delete confirmed");
    //redirect to journal page
    //router.push('/journal');
  }

  {/* For Conditionally Displaying Delete Confirmation */}
  const showDeleteConfirmation = (e: React.MouseEvent<HTMLButtonElement>) => {
    e.preventDefault();
    setDeleteConfirmation(false);
  } 

  const handlePrivacy = async () => {
    console.log("Button clicked");
    const privacy = !journalEntry?.IS_PRIVATE;
    try {
      if (journalEntry && journalEntry._id) {
        await setJournalEntryPrivacy(journalEntry._id, privacy);
        dispatch(updateJournalEntryPrivacy({ entryId: journalEntry?._id, privacy }));
        console.log("Privacy updated");
        setAddSuccess('Changed privacy setting to ' + (privacy ? 'Private' : 'Public'));  
        setShowMenu(!showMenu);
        setTimeout(() => {
          setTimeout(() => {
            router.push('/journal');
          }, 2500);
        }, 2000);
      } else {
        console.error('Journal entry or journal entry ID is undefined');
      }
    } catch (error) {
      console.error('Failed to update journal entry privacy: ', error);
    }
  }


  return (
    <>

    <div className="border-[2px] border-green-500 rounded m-4 flex flex-col relative">
      <div className="w-full max-w-full rounded overflow-hidden pt-2">
        <div className="flex items-center">
            
            <Link href={userProfileLink} className="ml-2">
              <div className="flex items-center">
                <div className="w-16 h-16">
                  <Image
                    src="/jonathan.jpg"
                    alt="Profile picture"
                    layout="responsive"
                    width={100}
                    height={100}
                    className="rounded-full object-cover border-2 border-green-500"
                  />
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
              <div className="absolute right-0 top-0 mt-12 mr-4 bg-white border-[2px] border-dotted border-green-500 rounded p-2">
                <Link href={`/journal/editJournalEntry/${journalEntry?._id}`}>
                  <p className="text-gray-700 text-sm font-bold py-1">Edit</p>
                </Link>
                {/* Juan: this handles display of delete confirmation window*/}
                  <p className="text-gray-700 text-sm font-bold py-1">Delete</p>  
                  <p className="text-gray-700 text-sm font-bold py-1">Change Status</p>


              </div>
            ) : null}

            
          </div>

          <div className='border-green-500 border-2 rounded m-2'>
          <Image
            className="w-full h-auto"
            src={imgSrc}
            alt="Sunset in the mountains"
            width={500}
            height={300}
          />
          </div>

          <div className="px-2 py-2">
              <div className="font-bold text-xl mb-2">{`${journalEntry?.TITLE}`}</div>
                  <p className="text-gray-700 text-base pb-4">
                    {journalEntry?.BODY} 
                  </p>
                  <div className="flex justify-between items-center">
                  <p className="text-gray-500 text-sm font-bold py-1">{`${journalEntry?.DATE.substring(0, 10)}`}</p>
                  <p className="text-gray-500 text-sm font-bold py-1">{`${journalEntry?.LOCATION}`}</p>
                  <div className="flex justify-end items-center">
                <div className={`h-3 w-3 rounded-full ${journalEntry?.IS_PRIVATE ? 'bg-amber-500' : 'bg-green-500'} mr-1`}></div>
              <p className = "text-sm">{journalEntry?.IS_PRIVATE ? 'Private' : 'Public'}</p>
            </div>
          </div>

          </div>
        </div>
      </div>

      {deleteConfirmation &&
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full flex justify-center items-center z-10">
          <div className="bg-white p-5 rounded-lg shadow-xl">
              <h2 className="text-lg font-semibold mb-4 text-center">Confirm Deletion</h2>
              <p className="mb-4 justify-center text-center">Are you sure you want <br/> to delete this entry?</p>
              <div className="flex justify-between">
                  <button onClick={showDeleteConfirmation} className="bg-gray-300 text-gray-700 px-4 py-2 ml-5 rounded hover:bg-gray-400">No</button> 
                  <button onClick={handleDelete} className="bg-red-500 text-white px-4 py-2 mr-5 rounded hover:bg-red-600">Yes</button>
              </div>
          </div>
        </div>
      }
    </>
  )
}

export default DetailedPost