'use client';

import React, { useState, ChangeEvent, FormEvent } from 'react';
import Link from 'next/link'; 
import {ArrowCircleLeftIcon} from '@heroicons/react/outline';
import { RootState } from '@/store/store';
import { useSelector } from 'react-redux';
import { submitThread } from '@/lib/userData';
import CustomLayout from '@/components/CustomLayout';
import { useRouter } from 'next/navigation';
import ReactGoogleAutocomplete from 'react-google-autocomplete';
//
interface EntryData {
  title: string;
  text: string;
  attachment: File | null;
  location: string;
  latitude: number;
  longitude: number;
}

const AddNewThread = () => {
  const [entryData, setEntryData] = useState<EntryData>({
    title: '',
    text: '',
    attachment: null,
    location: '',
    latitude: 0,
    longitude: 0,
  });

  const router = useRouter();
  const user = useSelector((state: RootState) => state.user);

  const [imageFile, setImage] = useState<File | null>(null);
  const [addSuccess, setAddSuccess] = useState('');
  const [starCount, setStarCount] = useState(0);

  const handleInputChange = (e: ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    const { name, value } = e.target;
    setEntryData({ ...entryData, [name]: value });
  };

  const handleImageChange = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    console.log(file);
    if (file) {
      setEntryData({ ...entryData, attachment: file });
    } else {
      setEntryData({ ...entryData, attachment: null });
    }
  };

const handleSubmit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
  
    const formData = new FormData();
    Object.entries(entryData).forEach(([key, value]) => {
      if (key === 'attachment' && value) {
        formData.append('attachments', value);
      } else if (key !== 'attachment') { 
        formData.append(key, String(value));
      }
    });


    submitThread(user._id, formData)
      .then(() => {
        console.log("Thread and Attachement uploaded successfully.");

        setAddSuccess('Thread created successfully');
      })
      .catch(err => console.error(err));
    };
    
    
    
    const addJournal = () => {
      setAddSuccess('Thread created successfully');
      setTimeout(() => {
        setTimeout(() => {
          router.push('/forum');
        }, 2500);
      }, 2000);
    }

  return (
    <>
    <CustomLayout showNavbar>
    {addSuccess && (
        <div className="bg-green-500 text-white px-4 py-2 rounded-xl">
          {addSuccess}
        </div>
      )}
    <div className="flex justify-center items-center">
      <div className="bg-white p-8 rounded-md">
      <div className="flex items-center mb-4">
          <Link href="/forum">
            <span className="cursor-pointer">
              <ArrowCircleLeftIcon className="h-12 w-12 mr-4" />
            </span>
          </Link>
          <h2 className="text-2xl font-bold">Create new <span className="text-green-500">Thread</span></h2>
        </div>
        
        <form onSubmit={handleSubmit} className="space-y-4">
          
        <div>
              <label htmlFor="location" className="block text-md font-medium text-black-900 font-sans">
                Location:
              </label>
              <ReactGoogleAutocomplete
                apiKey={process.env.NEXT_PUBLIC_GOOGLE_MAPS_API_KEY || ""}
                options={{types: ['establishment', 'geocode']}}
                onPlaceSelected={(place) => {
                  if (place.geometry && place.geometry.location) {
                    
                    setEntryData({ 
                      ...entryData, 
                      location: place.formatted_address || "",
                      latitude: place.geometry.location.lat(),
                      longitude: place.geometry.location.lng()
                      
                    });
                    console.log(place.geometry.location.lat())
                    console.log(place.geometry.location.lng())

                  } else {
                    console.error("Could not get the location of the selected place.");
                  }
                }}
                className="block w-full rounded-md border-0 py-1.5 pl-4 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
              />
            </div>
          
          <div>
            <label htmlFor="title" className="block text-md font-medium text-black-900 font-sans">
              Thread Title:
            </label>
            <input
              type="text"
              id="title"
              name="title"
              value={entryData.title}
              onChange={handleInputChange}
              className="block w-full rounded-md border-0 py-1.5 pl-4 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
              required
            />
          </div>
          
          <div>
            <label htmlFor="text" className="block text-md font-medium text-black-900 font-sans">
              Thread Text:
            </label>
            <textarea
              id="text"
              name="text"
              value={entryData.text}
              onChange={handleInputChange}
              className="block w-full h-48 rounded-md border-0 py-1.5 pl-4 text-black-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
              required
            />
          </div>

       
          
 
          <div className='pb-8'>
            <label htmlFor="image" className="block text-md font-medium text-black-900 font-sans">
              Add Photo or Video:
            </label>
            <input
              type="file"
              id="image"
              name="image"
              accept="image/*,video/*"
              onChange={handleImageChange}
              className="block w-full h-16 rounded-md border-0 py-1.5 pl-4 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-green-600 sm:text-sm sm:leading-6 font-sans"
            />
          </div>
          
 
         
 
          <div>
            {/* <Link href="/journal"> */}
              <button
                type="submit"
                className="w-full flex justify-center py-2 px-4 border border-transparent rounded-full shadow-sm text-md font-medium text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 font-sans"
                onClick={addJournal}
              >
                Create Thread
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
        </form>
      </div>
    </div>
    </CustomLayout>
    </>
  );
};
export default AddNewThread;