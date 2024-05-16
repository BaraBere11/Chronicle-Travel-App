'use client';

import React, { useState, ChangeEvent, FormEvent } from 'react';
import Link from 'next/link'; 
import {ArrowCircleLeftIcon} from '@heroicons/react/outline';
import { RootState } from '@/store/store';
import { useSelector } from 'react-redux';
import { submitJournalEntry } from '@/lib/userData';
import CustomLayout from '@/components/CustomLayout';
import { useRouter } from 'next/navigation';
import ReactGoogleAutocomplete from 'react-google-autocomplete';
import TopNavBar from '@/components/TopNavBar';
// import { getLatLng } from 'use-places-autocomplete';

interface EntryData {
  title: string;
  location: string;
  latitude: number;
  longitude: number;
  location_rating: number;
  text: string;
  is_private: boolean;
  attachment: File | null;
}

const AddJournalEntry = () => {
  const [entryData, setEntryData] = useState<EntryData>({
    title: '',
    location: '',
    latitude: 0,
    longitude: 0,
    location_rating: 0,
    text: '',
    is_private: false,
    attachment: null,
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


    submitJournalEntry(user._id, formData)
      .then(() => {
        console.log("Journal entry and image uploaded successfully.");

        setAddSuccess('Journal entry added successfully');
      })
      .catch(err => console.error(err));
    };
    
    
    
    const addJournal = () => {
      setAddSuccess('Journal entry added successfully');
      setTimeout(() => {
        setTimeout(() => {
          router.push('/journal');
        }, 2500);
      }, 2000);
    }

    const setLocationRating = (position: number) => {
      setStarCount(position);
      console.log("Star Count: ", position);
      setEntryData({ ...entryData, location_rating: position });
      console.log("Location Rating: ", entryData.location_rating);
    };
    



  return (
    <>
    <CustomLayout showNavbar>
    <TopNavBar />
    {addSuccess && (
        <div className="bg-green-500 text-white px-4 py-2 rounded-xl">
          {addSuccess}
        </div>
      )}
    <div className="flex justify-center items-center">
      <div className="bg-white p-2 rounded-md">
      <div className="flex items-center mb-4">
          <Link href="/home">
            <span className="cursor-pointer">
              <ArrowCircleLeftIcon className="h-12 w-12 mr-4" />
            </span>
          </Link>
          <h2 className="text-2xl font-bold">Add Journal <span className="text-green-500">Entry</span></h2>
        </div>
        
        <form onSubmit={handleSubmit} className="space-y-4">

        <div>
            <label htmlFor="location" className="block text-md font-medium text-black-900 font-sans">
              Location:
            </label>
            <ReactGoogleAutocomplete
              apiKey={process.env.NEXT_PUBLIC_GOOGLE_MAPS_API_KEY || ""}
              options={{types: ['establishment', 'geocode']}}
              onPlaceSelected={(place: any) => {
                if (place.geometry && place.geometry.location) {
                  setEntryData({ 
                    ...entryData, 
                    location: place.formatted_address || "",
                    latitude: place.geometry.location.lat(),
                    longitude: place.geometry.location.lng()
                  });
                  console.log(place.geometry.location.lat(),"latitude in add journal");
                  console.log(place.geometry.location.lng(),"longitude in add journal");
                } else {
                  console.error("Could not get the location of the selected place.");
                }
              }}
              
              className="block w-full rounded-md border-0 py-1.5 pl-4 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
            />
</div>

          <div>
            <label htmlFor="title" className="block text-md font-medium text-black-900 font-sans">
              Entry Title:
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
            <label htmlFor="location_rating" className="block text-md font-medium text-black-900 font-sans mb-3">
              Location Rating:  
            </label>
      
              <div className="flex items-center">



                <a onClick={()=>setLocationRating(1)}>
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

                  <a onClick={()=>setLocationRating(2)}>

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

                  <a onClick={()=>setLocationRating(3)}>
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

                  <a onClick={()=>setLocationRating(4)}>
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

                  <a onClick={()=>{setLocationRating(5); 
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

              </div>


          </div>
          
          <div>
            <label htmlFor="text" className="block text-md font-medium text-black-900 font-sans">
              Entry Text:
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
          
         
          <div className='flex justify-center items-center'>
           
            {/*Privacy*/}
            <label className="inline-flex items-center cursor-pointer">
              <input
                  type="checkbox"
                  id="is_private"
                  name="is_private"
                  checked={entryData.is_private}
                  onChange={(e) => setEntryData({ ...entryData, is_private: e.target.checked })}  
                  className="sr-only peer">
                </input>
              <div className="relative w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 dark:peer-focus:ring-green-800 rounded-full peer dark:bg-green-700 peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-orange-400"></div>
              <span className="ms-3 text-sm font-medium text-gray-900 dark:text-black">
                {/*If is_private is true, label will display word "Private", otherwise displays "Public"*/}
                {entryData.is_private ? 'Private' : 'Public'}
              </span>
            </label>
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
                Add Entry
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
export default AddJournalEntry;

