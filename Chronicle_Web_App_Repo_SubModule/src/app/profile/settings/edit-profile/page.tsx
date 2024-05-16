'use client'

import React from 'react';
import Image from 'next/image';
import Link from 'next/link'; 
import CustomLayout from '@/components/CustomLayout';
import { RootState } from '@/store/store';
import { useSelector} from 'react-redux';
import { CogIcon, UserCircleIcon, ArrowCircleLeftIcon, PencilIcon, LockClosedIcon, ChatIcon, InformationCircleIcon, ChevronRightIcon} from '@heroicons/react/outline';
import RoundedGreenButton from '@/components/rounded-green-button';
import Cookies from "js-cookie";
import fetchImage from '../../../../lib/attachments';

import { useForm } from 'react-hook-form';
import { useState, useEffect } from 'react';

import { updateUser, deleteUser } from '@/lib/userData';
import { UserData} from '@/store/UserSlice'
import { setUser } from '@/store/UserSlice';
import { useDispatch } from 'react-redux'
import TopNavBar from '@/components/TopNavBar';


const EditProfilePage = () => {

  const [imgSrc, setImgSrc] = useState('');

  const dispatch = useDispatch();

  const [warning, setWarning] = useState('');
  const [successMessage, setSuccessMessage] = useState('');

  const [showDeleteConfirmation, setShowDeleteConfirmation] = useState(false);
  const [confirmUsername, setConfirmUsername] = useState('');

  const [deleteError, setDeleteError] = useState('');
  const [deleteSuccess, setDeleteSuccess] = useState('');

  const [avatar, setAvatar] = useState<File | null>(null);

  const user = useSelector((state: RootState) => state.user);

  const imageId = user.PROFILE_IMAGE_ID;

  type FormData = {
    firstName: string;
    lastName: string;
    email: string;
  };
//
  const { register, handleSubmit } = useForm({
    defaultValues: {
      firstName: user.FIRST_NAME, 
      lastName: user.LAST_NAME,
      email: user.EMAIL_ADDRESS,
    },
  });

  useEffect(() => {
    fetchImage(imageId)
      .then(setImgSrc)
      .catch(() => setImgSrc(''));
  }, [imageId]);

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  async function submitForm(data: FormData) {

    setWarning('');

    const { firstName, lastName, email } = data;

    

    //validation here
    if (!emailRegex.test(email)) {
      setWarning("Invalid email format");
      return;
    }

    const updatedUserData = {
      ...user, 
      FIRST_NAME: firstName,
      LAST_NAME: lastName,
      EMAIL_ADDRESS: email,
      AVATAR: avatar
    };

    const formData = new FormData();
    formData.append('firstName', firstName);
    formData.append('lastName', lastName);
    formData.append('email', email);
    if (avatar) {
      formData.append('avatar', avatar);
    }

    try {
      let id = user._id;
      if (id) {
        let userDataRes = await updateUser(id, formData);
        console.log("User data Check 2: ", userDataRes);
        
        updateUserSlice(userDataRes.data);

        setSuccessMessage('Profile updated successfully!');

      } else {
        setWarning('Authentication failed');
      }
    } catch (err) {
      if (err instanceof Error) {
        setWarning(err.message);
      } else {
        throw err;
      }
    }
  }

  const deleteProfile = () => {
    setShowDeleteConfirmation(true);
  };

  const handleDelete = async () => {
    if (confirmUsername === user.USER_NAME) {
      try {
        await deleteUser(user._id);
        setDeleteSuccess('Profile successfully deleted.');
        Cookies.remove("loggedIn")
        setTimeout(() => {
          window.location.href = '/';
        }, 2000);
      } catch (error) {
        showErrorForDuration('Failed to delete profile. Please try again.');
      }
    } else {
      showErrorForDuration('Username does not match. Please enter the correct username to confirm deletion.');
    }
  
    setShowDeleteConfirmation(false);
    setConfirmUsername('');
  };

  const renderDeleteConfirmation = () => (
    <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full flex justify-center items-center">
      <div className="bg-white p-5 rounded-lg shadow-xl">
        <h2 className="text-lg font-semibold mb-4">Confirm Deletion</h2>
        <p className="mb-4">Type your username to confirm:</p>
        <input 
          title="confirm-username"
          type="text" 
          value={confirmUsername} 
          onChange={(e) => setConfirmUsername(e.target.value)}
          className="border border-gray-300 p-2 rounded-md mb-4 w-full"
        />
        <div className="flex justify-between">
          <button onClick={handleDelete} className="bg-red-500 text-white px-4 py-2 rounded hover:bg-red-600">Confirm Delete</button>
          <button onClick={() => setShowDeleteConfirmation(false)} className="bg-gray-300 text-gray-700 px-4 py-2 rounded hover:bg-gray-400">Cancel</button>
        </div>
      </div>
    </div>
  );

  const showErrorForDuration = (errorMessage: string) => {
    setDeleteError(errorMessage);
    setTimeout(() => {
      setDeleteError('');
    }, 3000); 
  };
  

  async function updateUserSlice(userDataRes:UserData) {
    const userReduxData = {
      _id: userDataRes._id,
      USER_NAME: userDataRes.USER_NAME,
      PASSWORD: userDataRes.PASSWORD, 
      CONFIRM_PASSWORD: userDataRes.CONFIRM_PASSWORD, 
      EMAIL_ADDRESS: userDataRes.EMAIL_ADDRESS,
      TERMS: userDataRes.TERMS,
      FIRST_NAME: userDataRes.FIRST_NAME,
      LAST_NAME: userDataRes.LAST_NAME,
      IS_ACTIVE: userDataRes.IS_ACTIVE,
      DATE_CREATED: userDataRes.DATE_CREATED,
      PROFILE_IMAGE_ID: userDataRes.PROFILE_IMAGE_ID
    };
  
    console.log("Updated Redux Store:", userReduxData);
    console.log("User Email: " , userReduxData.EMAIL_ADDRESS);
    dispatch(setUser(userReduxData));
    
  } 
  
  const handleAvatarChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files ? event.target.files[0] : null;
    if (file) {
      setAvatar(file);
    }
  };
  
  return (
    <CustomLayout showNavbar>
      <TopNavBar />
      {successMessage && (
        <div className="bg-green-500 text-white px-4 py-2 rounded-xl">
          {successMessage}
        </div>
      )}

      <div className="flex justify-center items-center h-full">
        <div className='flex flex-col min-h-screen py-4'>
          <div className="flex flex-col min-h-screen py-1 px-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center">
                <Link href="/profile/settings">
                  <span className="cursor-pointer">
                    <ArrowCircleLeftIcon className="h-12 w-12 mr-4"/>
                  </span>
                </Link>
                <h2 className="text-2xl font-bold text-">Edit <span className="text-green-500 mr-12">Profile</span></h2>
              </div>
            </div>

          {imgSrc ? (
                <div className='flex flex-col items-center pb-4 pt-6'>


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


            { /* Form */}
            <div className="flex flex-col space-y-1 py-1 justify-center items-center">
              <form onSubmit={handleSubmit(submitForm)} className="flex flex-col py-6 space-y-2 w-2/3">
               <label className="font-semibold text-sm">
                First Name
               </label>
               
                <input 
                {...register('firstName')}
                className="text-black outline-black border border-black rounded outline-1 pl-2 h-10" 
                placeholder={user.FIRST_NAME} 
                />
                
                <label className="font-semibold text-sm">
                  Last Name
                </label>
               
                <input 
                {...register('lastName')}
                className="text-black outline-black border border-black rounded outline-1 pl-2 h-10"
                placeholder={user.LAST_NAME}
                />
               
                <label className="font-semibold text-sm">
                  Email
                </label>
               
                <input 
                {...register('email')}
                className="text-black outline-black border border-black rounded outline-1 pl-2 h-10"
                placeholder={user.EMAIL_ADDRESS}
                />

        { /* Warning */ }
                    {warning && (
                      <div className="bg-red-500 text-white px-4 py-2 rounded-1xl">
                          {warning}
                      </div>
                      )}
        
        
        <div className="flex flex-col items-center">
          <label htmlFor="avatar-upload" className="block text-md font-medium text-black-900 font-sans">
            <div className="flex flex-col items-center p-6">
              <p>Update your profile photo here</p>
            </div>
          </label>



          <input 
            id="avatar-upload"
            type="file"
            accept="image/*"
            onChange={handleAvatarChange}
            className=" w-full p-8 block rounded-md border-0 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-green-600 sm:text-sm sm:leading-6 font-sans"
          />





        </div>
        { /* Update Button */ }
                <div className="flex flex-col space-y-2 pt-6 pb-2 justify-center items-center">
                    <RoundedGreenButton type="submit" text="Update Profile"/>
                </div>
             </form>

             { /* Delete Profile Button */ }
             <button className="py-3 rounded-3xl border-2 border-red-600 bg-white px-6 text-xs font-medium uppercase leading-tight hover:bg-gray-100 text-red-600 shadow-md transition duration-150 ease-in-out hover:shadow-lg focus:shadow-lg focus:outline-none active:shadow-lg m-6 w-[150px]"
                       onClick={deleteProfile}>
                        Delete Profile
                        </button>
                {/* <div className="flex flex-col space-y-4 py-8 justify-center items-center">
                    <button onClick={deleteProfile}>Delete Profile</button>
                </div> */}
        </div>
          </div>
        </div>
        {deleteSuccess && (
          <div className="fixed inset-0 bg-gray-600 bg-opacity-50 flex justify-center items-center">
              <div className="bg-green-500 text-white px-4 py-2 rounded-xl shadow-lg">
                  {deleteSuccess}
              </div>
          </div>
      )}
      {deleteError && (
          <div className="fixed inset-0 bg-gray-600 bg-opacity-50 flex justify-center items-center">
              <div className="bg-red-500 text-white px-4 py-2 rounded-xl shadow-lg">
                  {deleteError}
              </div>
          </div>
      )}

      {showDeleteConfirmation && renderDeleteConfirmation()}

      </div>
    </CustomLayout>
  )
}

export default EditProfilePage;