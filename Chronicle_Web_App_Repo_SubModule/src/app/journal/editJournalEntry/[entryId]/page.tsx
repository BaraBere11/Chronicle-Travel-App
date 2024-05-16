"use client";

import React, { useState, ChangeEvent, FormEvent, useEffect, useRef } from 'react';
import Link from 'next/link'; 
import { ArrowCircleLeftIcon } from '@heroicons/react/outline';
import { JournalEntry } from '@/store/UserSlice';
import {getJournalEntryById, updateJournalEntry} from '@/lib/userData';
import Image from 'next/image';
import fetchImage from '@/lib/attachments';
import { useSelector } from 'react-redux';
import { RootState } from '@/store/store';
import CustomLayout from '@/components/CustomLayout';
import {useRouter} from 'next/navigation';
import { set } from 'react-hook-form';
import TopNavBar from '@/components/TopNavBar';
import ReactGoogleAutocomplete from 'react-google-autocomplete';

type JournalEntryIDProps = {
  params: {
    entryId: string;
  };
}

const EditJournalEntry = ({params} : JournalEntryIDProps)=> {

  // const autocompleteRef = useRef(null);
  const router = useRouter();
  const [title, setTitle] = useState('');
  const [location, setLocation] = useState('');
  const [latitude, setLongitude] = useState(0);
  const [longitude, setLatitude] = useState(0);
  const [text, setText] = useState('');
  const [attachment, setAttachment] = useState<File | null>(null);
  const [privacy, setPrivacy] = useState(false);
  const [starCount, setStarCount] = useState(0);
  const [initialLongitude, setInitialLongitude] = useState(0);
  const [initialLatitude, setInitialLatitude] = useState(0);

  const user = useSelector((state: RootState) => state.user);

  // fetch journalEntry by id
  const [entryData, setEntryData] = useState<JournalEntry>();
  const [editSuccess, setEditSuccess] = useState('');

  useEffect(() => {
    const fetchJournalEntry = async () => {
      const entry = await getJournalEntryById(params.entryId);
      console.log("EDIT JOURNAL ENTRY: ")
      setEntryData(entry);
    }
    fetchJournalEntry(); // Call the function
  }, [params.entryId]); // Add dependency array

  //load entry data into form
  useEffect(() => {
    if (entryData) {
      setTitle(entryData.TITLE ?? '');
      setLocation(entryData.LOCATION ?? '');
      setLongitude(entryData.LONGITUDE ?? 0);
      setLatitude(entryData.LATITUDE ?? 0);
      setInitialLongitude(entryData.LONGITUDE ?? 0); 
      setInitialLatitude(entryData.LATITUDE ?? 0); 
      setText(entryData.BODY ?? '');
      setPrivacy(entryData.IS_PRIVATE);
      setStarCount(entryData.LOCATION_RATING ?? 0);

      console.log("Location Rating: ", entryData.LOCATION_RATING)
      //setStarCount(entryData.LOCATION_RATING);
    }
  }, [entryData]);
    
  const [imgSrc, setImgSrc] = useState('');
  const imageId = entryData?.ATTACHMENT_IDS[0]

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

  //handle change in form input

  const handleTitleChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setTitle(event.target.value);
  };
  
  const handleLocationChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setLocation(event.target.value);
  };
  
  const handleTextChange = (event: React.ChangeEvent<HTMLTextAreaElement>) => {
    setText(event.target.value);
  };
  
  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setAttachment(event.target.files ? event.target.files[0] : null);
  };

  const handlePrivacyChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setPrivacy(event.target.checked);
  };

  const handleLocationRatingChange = (rating: number) => {
    setStarCount(rating);
  }

  //submit form to update journal entry
  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    console.log("Edit Journal Entry Button clicked");

    const currentLongitude = location !== entryData?.LOCATION ? longitude : initialLongitude;
    const currentLatitude = location !== entryData?.LOCATION ? latitude : initialLatitude;

    const updatedFormData = new FormData();
    updatedFormData.append('title', title);
    updatedFormData.append('location', location);
    updatedFormData.append('latitude', currentLatitude.toString());
    updatedFormData.append('longitude', currentLongitude.toString());
    updatedFormData.append('text', text);
    updatedFormData.append('is_private', String(privacy));
    updatedFormData.append('location_rating', String(starCount));
    if (attachment) {
      updatedFormData.append('attachments', attachment);
    }
    Object.entries(updatedFormData).forEach(([key, value]) => {
      if (key === 'attachment' && value) {
        updatedFormData.append('attachments', value);
      } else if (key !== 'attachment') { 
        updatedFormData.append(key, String(value));
      }
    });

    console.log("calling updateJournalEntry function with entryId: ", entryData?._id ?? '');
    updateJournalEntry(user._id, updatedFormData, entryData?._id ?? '')
      .then(() => {
        console.log("Journal entry and image UPDATED successfully.");
      })
      .catch(err => console.error(err));

    setEditSuccess('Journal entry edited successfully');
    setTimeout(() => {
      setTimeout(() => {
        router.push('/journal');
      }, 2000);
    }, 2000);
  };

  const handlePlaceSelected = (place: google.maps.places.PlaceResult) => {
    if (place.geometry && place.formatted_address) {
        const { location } = place.geometry;
        
        if (location) {
            const latitude = location.lng();
            const longitude = location.lat();
            const formattedAddress = place.formatted_address;
            
            setLatitude(latitude);
            setLongitude(longitude);
            setLocation(formattedAddress);
        } else {
            console.error('The place does not have a valid location.');
        }
    } else {
        console.error('The place has no valid geometry.');
    }
};


  return (
    <>
    <CustomLayout showNavbar>
      <TopNavBar />
    {editSuccess && (
      <div className="bg-green-500 text-white ml-2 mr-2 px-2 py-2 text-md rounded-md justify-center text-center">
        <div className="bg-green-500 text-white px-4 py-2 rounded-xl">
          {editSuccess}
        </div>
      </div>
      )}
    <div className="flex justify-center items-center">
    <div className="bg-white pt-2 pl-6 pr-6 rounded-md">
    <div className="flex items-center mb-4">
        <Link href="/home">
          <span className="cursor-pointer">
            <ArrowCircleLeftIcon className="h-12 w-12 mr-4" />
          </span>
        </Link>
        <h2 className="text-2xl font-bold">Edit Journal <span className="text-green-500">Entry</span></h2>
      </div>
      
      <form onSubmit={handleSubmit} className="space-y-2">
        <div>
          <label htmlFor="title" className="block text-md font-medium text-black-900 font-sans">
            Entry Title:
          </label>
          <input
            type="text"
            id="title"
            name="title"
            value={title}
            onChange={handleTitleChange}
            className="block w-full rounded-md border-0 py-1.5 pl-4 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
            required
          />
        </div>
        
        <div>
          <label htmlFor="location" className="block text-md font-medium text-black-900 font-sans">
            Location:
          </label>
          <ReactGoogleAutocomplete
            apiKey={process.env.NEXT_PUBLIC_GOOGLE_MAPS_API_KEY || ''}
            options={{types: ['establishment', 'geocode']}}
            onPlaceSelected={handlePlaceSelected}
            value={location}
            onChange={handleLocationChange}
            className="block w-full rounded-md border-0 py-1.5 pl-4 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
        />
        </div>

        <div>
            <label htmlFor="location_rating" className="block text-md font-medium text-black-900 font-sans mb-3">
              Location Rating:  
            </label>
      
              <div className="flex items-center">



                <a onClick={()=>handleLocationRatingChange(1)}>
                  {/* If locationRating is 0, the star will be gray, otherwise it will be yellow*/}

                  {starCount > 0 ?
                    <svg className="w-6 h-6 text-yellow-300 ms-1" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 22 20">
                      <path d="M20.924 7.625a1.523 1.523 0 0 0-1.238-1.044l-5.051-.734-2.259-4.577a1.534 1.534 0 0 0-2.752 0L7.365 5.847l-5.051.734A1.535 1.535 0 0 0 1.463 9.2l3.656 3.563-.863 5.031a1.532 1.532 0 0 0 2.226 1.616L11 17.033l4.518 2.375a1.534 1.534 0 0 0 2.226-1.617l-.863-5.03L20.537 9.2a1.523 1.523 0 0 0 .387-1.575Z"/>
                      </svg>
                      :
                      <svg className="w-6 h-6 ms-1 text-gray-300 dark:text-gray-500" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 22 20">
                        <path d="M20.924 7.625a1.523 1.523 0 0 0-1.238-1.044l-5.051-.734-2.259-4.577a1.534 1.534 0 0 0-2.752 0L7.365 5.847l-5.051.734A1.535 1.535 0 0 0 1.463 9.2l3.656 3.563-.863 5.031a1.532 1.532 0 0 0 2.226 1.616L11 17.033l4.518 2.375a1.534 1.534 0 0 0 2.226-1.617l-.863-5.03L20.537 9.2a1.523 1.523 0 0 0 .387-1.575Z"/>
                        </svg>
                        }
                </a>

                  <a onClick={()=>handleLocationRatingChange(2)}>

                  {starCount > 1 ?  
                  <svg className="w-6 h-6 text-yellow-300 ms-1" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 22 20">
                      <path d="M20.924 7.625a1.523 1.523 0 0 0-1.238-1.044l-5.051-.734-2.259-4.577a1.534 1.534 0 0 0-2.752 0L7.365 5.847l-5.051.734A1.535 1.535 0 0 0 1.463 9.2l3.656 3.563-.863 5.031a1.532 1.532 0 0 0 2.226 1.616L11 17.033l4.518 2.375a1.534 1.534 0 0 0 2.226-1.617l-.863-5.03L20.537 9.2a1.523 1.523 0 0 0 .387-1.575Z"/>
                  </svg>
                  :
                  <svg className="w-6 h-6 ms-1 text-gray-300 dark:text-gray-500" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 22 20">
                      <path d="M20.924 7.625a1.523 1.523 0 0 0-1.238-1.044l-5.051-.734-2.259-4.577a1.534 1.534 0 0 0-2.752 0L7.365 5.847l-5.051.734A1.535 1.535 0 0 0 1.463 9.2l3.656 3.563-.863 5.031a1.532 1.532 0 0 0 2.226 1.616L11 17.033l4.518 2.375a1.534 1.534 0 0 0 2.226-1.617l-.863-5.03L20.537 9.2a1.523 1.523 0 0 0 .387-1.575Z"/>
                  </svg>
                  }

                  </a>

                  <a onClick={()=>handleLocationRatingChange(3)}>
                  {starCount > 2 ?  
                  <svg className="w-6 h-6 text-yellow-300 ms-1" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 22 20">
                      <path d="M20.924 7.625a1.523 1.523 0 0 0-1.238-1.044l-5.051-.734-2.259-4.577a1.534 1.534 0 0 0-2.752 0L7.365 5.847l-5.051.734A1.535 1.535 0 0 0 1.463 9.2l3.656 3.563-.863 5.031a1.532 1.532 0 0 0 2.226 1.616L11 17.033l4.518 2.375a1.534 1.534 0 0 0 2.226-1.617l-.863-5.03L20.537 9.2a1.523 1.523 0 0 0 .387-1.575Z"/>
                  </svg>
                  :
                  <svg className="w-6 h-6 ms-1 text-gray-300 dark:text-gray-500" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 22 20">
                      <path d="M20.924 7.625a1.523 1.523 0 0 0-1.238-1.044l-5.051-.734-2.259-4.577a1.534 1.534 0 0 0-2.752 0L7.365 5.847l-5.051.734A1.535 1.535 0 0 0 1.463 9.2l3.656 3.563-.863 5.031a1.532 1.532 0 0 0 2.226 1.616L11 17.033l4.518 2.375a1.534 1.534 0 0 0 2.226-1.617l-.863-5.03L20.537 9.2a1.523 1.523 0 0 0 .387-1.575Z"/>
                  </svg>
                  }
                  </a>

                  <a onClick={()=>handleLocationRatingChange(4)}>
                  {starCount > 3 ?  
                  <svg className="w-6 h-6 text-yellow-300 ms-1" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 22 20">
                      <path d="M20.924 7.625a1.523 1.523 0 0 0-1.238-1.044l-5.051-.734-2.259-4.577a1.534 1.534 0 0 0-2.752 0L7.365 5.847l-5.051.734A1.535 1.535 0 0 0 1.463 9.2l3.656 3.563-.863 5.031a1.532 1.532 0 0 0 2.226 1.616L11 17.033l4.518 2.375a1.534 1.534 0 0 0 2.226-1.617l-.863-5.03L20.537 9.2a1.523 1.523 0 0 0 .387-1.575Z"/>
                  </svg>
                  :
                  <svg className="w-6 h-6 ms-1 text-gray-300 dark:text-gray-500" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 22 20">
                      <path d="M20.924 7.625a1.523 1.523 0 0 0-1.238-1.044l-5.051-.734-2.259-4.577a1.534 1.534 0 0 0-2.752 0L7.365 5.847l-5.051.734A1.535 1.535 0 0 0 1.463 9.2l3.656 3.563-.863 5.031a1.532 1.532 0 0 0 2.226 1.616L11 17.033l4.518 2.375a1.534 1.534 0 0 0 2.226-1.617l-.863-5.03L20.537 9.2a1.523 1.523 0 0 0 .387-1.575Z"/>
                  </svg>
                  }
                  </a>

                  <a onClick={()=>{handleLocationRatingChange(5); 
                    console.log('New Location Rating: ', 5);}}>
                  {starCount > 4 ?  
                  <svg className="w-6 h-6 text-yellow-300 ms-1" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 22 20">
                      <path d="M20.924 7.625a1.523 1.523 0 0 0-1.238-1.044l-5.051-.734-2.259-4.577a1.534 1.534 0 0 0-2.752 0L7.365 5.847l-5.051.734A1.535 1.535 0 0 0 1.463 9.2l3.656 3.563-.863 5.031a1.532 1.532 0 0 0 2.226 1.616L11 17.033l4.518 2.375a1.534 1.534 0 0 0 2.226-1.617l-.863-5.03L20.537 9.2a1.523 1.523 0 0 0 .387-1.575Z"/>
                  </svg>
                  :
                  <svg className="w-6 h-6 ms-1 text-gray-300 dark:text-gray-500" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 22 20">
                      <path d="M20.924 7.625a1.523 1.523 0 0 0-1.238-1.044l-5.051-.734-2.259-4.577a1.534 1.534 0 0 0-2.752 0L7.365 5.847l-5.051.734A1.535 1.535 0 0 0 1.463 9.2l3.656 3.563-.863 5.031a1.532 1.532 0 0 0 2.226 1.616L11 17.033l4.518 2.375a1.534 1.534 0 0 0 2.226-1.617l-.863-5.03L20.537 9.2a1.523 1.523 0 0 0 .387-1.575Z"/>
                  </svg>
                  }
                  </a>

                  {/* add an option to remove all the stars in the location rating
                  create a button to remove ratings */}
                  <div className="flex items-center">
                    <p onClick={()=>{handleLocationRatingChange(0); console.log('New Location Rating: ', 0);}} className="text-red-500 ml-32">Remove All</p>
                  </div>



              </div>
              </div>
        
        <div>
          <label htmlFor="text" className="block text-md font-medium text-black-900 font-sans">
            Entry Text:
          </label>
          <textarea
            id="text"
            name="text"
            value={text}
            onChange={handleTextChange}
            className="block w-full h-32 rounded-md border-0 py-1.5 pl-4 text-black-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
            required
          />
        </div>
        <div className='flex justify-center items-center'>
           
            {/*Privacy*/}
            <label className="inline-flex items-center cursor-pointer">
              <input
                  type="checkbox"
                  id="is_private"
                  name="is_private"
                  checked={privacy}
                  onChange={handlePrivacyChange}  
                  className="sr-only peer">
                </input>
              <div className="relative w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 dark:peer-focus:ring-green-800 rounded-full peer dark:bg-green-700 peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-orange-400"></div>
              <span className="ms-3 text-sm font-medium text-gray-900 dark:text-black">
                {/*If is_private is true, label will display word "Private", otherwise displays "Public"*/}
                {privacy ? 'Private' : 'Public'}
              </span>
            </label>
          </div>
        {/**Image Attachment */}
        <div>
          <label htmlFor="image" className="block text-md font-medium text-black-900 font-sans">
            Attached Photo:
          </label>
          <div className="flex items-center justify-center">
            {imgSrc && imgSrc.startsWith("https") ? (
                      <video width="500" height="300" controls>
                        <source src={imgSrc} type={`video/${imgSrc.split('.').pop()?.split('?')[0] || 'mp4'}`} />
                        Your browser does not support the video tag.
                      </video>
                  ) : (
                    <Image
                        className=" w-1/2 h-1/2"
                        src={imgSrc}
                        alt="Sunset in the mountains"
                        width={100}
                        height={200}
                      />
                  )}
          </div>
        </div>
        
        <div className='pb-4'>
          <label htmlFor="image" className="block text-md font-medium text-black-900 font-sans">
            Add Photo:
          </label>
          <input
            type="file"
            id="image"
            name="image"
            accept="image/*"
            onChange={handleFileChange}
            className="block w-full rounded-md border-0 py-1.5 pl-4 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-green-600 sm:text-sm sm:leading-6 font-sans"
          />
        </div>
        
        <div>
            {/* <Link href="/journal"> */}
          <button
            type="submit"
            className="w-full flex justify-center py-2 px-4 border border-transparent rounded-full shadow-sm text-md font-medium text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 font-sans"
          >
            Edit Entry
          </button>
             {/* </Link> */}
        </div>
  
        <div>
          <Link href="/home">
            <button className="w-full flex justify-center py-2 px-4 border border-transparent rounded-full shadow-sm text-md font-medium text-white bg-gray-500 hover:bg-gray-300 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500 font-sans">
              Discard
            </button>
          </Link>
        </div>
        <br />
        <br />
      </form>
    </div>
    </div>
    </CustomLayout>
    </>
  );
};

export default EditJournalEntry;