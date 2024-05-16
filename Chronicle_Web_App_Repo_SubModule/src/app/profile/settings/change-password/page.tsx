'use client';

import React, { useState, ChangeEvent, FormEvent } from 'react';
import Link from 'next/link'; 
import {ArrowCircleLeftIcon} from '@heroicons/react/outline';
import CustomLayout from '@/components/CustomLayout';
import { useForm } from 'react-hook-form';
import RoundedGreenButton from '@/components/rounded-green-button';
import RoundedGreyButton from '@/components/Rounded-Grey-Button';
import { useRouter } from 'next/navigation';
import { useSelector } from 'react-redux';
import { RootState } from '@/store/store';
import { changeUserPassword } from '@/lib/userData';
import { UserData} from '@/store/UserSlice'
import { setUser } from '@/store/UserSlice';
import { useDispatch } from 'react-redux'
import { BsFillEyeSlashFill, BsEyeFill } from 'react-icons/bs';
import TopNavBar from '@/components/TopNavBar';


const ChangePassword = () => {

  const dispatch = useDispatch();
  const router = useRouter();
  const user = useSelector((state: RootState) => state.user);

  const [warning, setWarning] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  const [showOldPassword, setOldShowPassword] = useState(false);
  const [showNewPassword, setNewShowPassword] = useState(false);
  const [showConfNewPassword, setConfNewShowPassword] = useState(false);

  type cpData = {
    oldPassword: string;
    newPassword: string;
    confirmNewPassword: string;
  };  

  const {
    register,
    handleSubmit,
    formState: { errors },
    reset,
  } = useForm<cpData>({
    defaultValues: {
      oldPassword: "",
      newPassword: "",
      confirmNewPassword: "",
    },
  });

  async function submitForm(data: cpData) {

    console.log("inside submit Form: ", data.oldPassword, data.newPassword, data.confirmNewPassword);
    console.log("user name: ", user.USER_NAME);    
    console.log("user: ", user);

    // This should be the plaintext password that you want to compare with the hash
    let oldPasswordInput = data.oldPassword;
    let oldPassword = user.PASSWORD;
    console.log("Old User Password: ", oldPassword);
    console.log("data.oldPassword: ", data.oldPassword);

  
      console.log("Old Password matches");

      const updatedPasswordData = {
        ...user,
        PASSWORD: data.newPassword,
        CONFIRM_PASSWORD: data.confirmNewPassword,
      };

      console.log("Updated User Password Data: ", updatedPasswordData);
    
    
      if(data.newPassword !== data.confirmNewPassword) {
        setWarning("New Password and Confirm New Password do not match");
        return;
      }

      // new Password length must be between 8 and 16 characters
      if (data.newPassword.length < 8 || data.newPassword.length > 16) {
        setWarning("New Password must be between 8 and 16 characters");
        return;
      }

      // new Password must contain at least one special character
      const specialCharacterRegex = /[!@#$%^&*?]/;
      if (!specialCharacterRegex.test(data.newPassword)) {
        setWarning(
          "New Password must contain at least one special character (!@#$%^&*?)"
        );
        return;
      }

      try {
        console.log("calling change Password function from inside submitForm:");
        let id = user._id;
        if(id){
          let userDataRes = await changeUserPassword(id, oldPasswordInput, updatedPasswordData);
          console.log("User data: ", userDataRes);
          
          updateUserSlice();

          setSuccessMessage('Password changed successfully!');
          setTimeout(() => {
            setTimeout(() => {
              router.push('/profile');
            }, 2000);
          }, 2000);
        }
        else {
          setWarning('Authentication failed');
        }
      }
      catch (err) {
        if (err instanceof Error) {
          setWarning(err.message);
        } else {
          throw err;
        }
      }

    async function updateUserSlice() {
      const userReduxData = {
        _id: user._id,
        USER_NAME: user.USER_NAME,
        PASSWORD: data.newPassword, 
        CONFIRM_PASSWORD: data.confirmNewPassword, 
        EMAIL_ADDRESS: user.EMAIL_ADDRESS,
        TERMS: user.TERMS,
        FIRST_NAME: user.FIRST_NAME,
        LAST_NAME: user.LAST_NAME,
        IS_ACTIVE: user.IS_ACTIVE,
        DATE_CREATED: user.DATE_CREATED,
        PROFILE_IMAGE_ID: user.PROFILE_IMAGE_ID
      };
    
      console.log("Password Updated Redux Store:", userReduxData);
      console.log("User Email: " , userReduxData.EMAIL_ADDRESS);
      dispatch(setUser(userReduxData));
      
    }  
  }
  //
  return (
    <>
      <CustomLayout showNavbar>
        <TopNavBar />
      <div className="flex justify-center items-center">
      <div className="bg-white p-10 rounded-md">
      <div className="flex items-center mb-10">
       
        <Link href="/profile/settings">
          <span className="cursor-pointer">
            <ArrowCircleLeftIcon className="h-12 w-12 mr-4" />
          </span>
        </Link>
        <h2 className="text-2xl font-bold text-">Change <span className="text-green-500 mr-12">Password</span></h2>
      </div>
        
        <form onSubmit={handleSubmit(submitForm)} className="space-y-8">
          
            <div>
              <label htmlFor="oldPassword" className="block text-md font-medium text-black-900 font-sans">
                Old Password:
              </label>
              <div className="relative">
                <input
                  {...register("oldPassword", {required: true})}
                  type={showOldPassword ? "text" : "password"}
                  id="oldPassword"
                  name="oldPassword"
                  className="block w-full rounded-md border-0 py-1.5 pl-4 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                />
                <button
                  type="button"
                  className="absolute inset-y-0 right-0 px-3 py-2"
                  onClick={() => setOldShowPassword(!showOldPassword)}
                >
                  {showOldPassword ? <BsEyeFill /> : <BsFillEyeSlashFill />}
                </button>
              </div>
              {errors.oldPassword && (
                <span className="text-red-500 text-xs italic font-bold">
                Please enter the Old Password.
                </span>
              )}
            </div>

            <div>
              <label htmlFor="newPassword" className="block text-md font-medium text-black-900 font-sans">
                New Password:
              </label>
              <div className="relative">
                <input
                  {...register("newPassword", {required: true})}
                  type={showNewPassword ? "text" : "password"}
                  id="newPassword"
                  name="newPassword"
                  className="block w-full rounded-md border-0 py-1.5 pl-4 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                />
                <button
                  type="button"
                  className="absolute inset-y-0 right-0 px-3 py-2"
                  onClick={() => setNewShowPassword(!showNewPassword)}
                >
                  {showNewPassword ? <BsEyeFill /> : <BsFillEyeSlashFill />}
                </button>
              </div>
              {errors.newPassword && (
                <span className="text-red-500 text-xs italic font-bold">
                Please enter the New Password.
                </span>
              )}
            </div>  

            <div>
              <label htmlFor="confirmNewPassword" className="block text-md font-medium text-black-900 font-sans">
                Confirm New Password:
              </label>
              <div className="relative">
                <input
                  {...register("confirmNewPassword", {required: true})}
                  type={showConfNewPassword ? "text" : "password"}
                  id="confirmNewPassword"
                  name="confirmNewPassword"
                  className="block w-full rounded-md border-0 py-1.5 pl-4 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                />
                <button
                  type="button"
                  className="absolute inset-y-0 right-0 px-3 py-2"
                  onClick={() => setConfNewShowPassword(!showConfNewPassword)}
                >
                  {showConfNewPassword ? <BsEyeFill /> : <BsFillEyeSlashFill />}
                </button>
              </div>
              {errors.confirmNewPassword && (
                <span className="text-red-500 text-xs italic font-bold">
                Please re-enter the New Password.
                </span>
              )}
          </div>

          <br />
          <br />
          <br />
          <br />
          <br />
          <br />
          
      
          {/* Warning */}

          {warning && !successMessage && (
            <span className="bg-red-500 text-white px-1 py-1 text-md rounded-md justify-center text-center">
              {warning}
            </span>
          )}

          {successMessage && (
            <div className="fixed inset-0 bg-gray-600 bg-opacity-50 flex justify-center items-center">
              <div className="bg-green-500 text-white px-1 py-1 text-md rounded-md justify-center text-center">
                {successMessage}
              </div>
            </div>
          )}

          <br />
          <br />


          <div className="flex flex-col items-center justify-center">
            <div className="flex flex-col w-[250px]">
              <RoundedGreenButton text="Change Password" type="submit" />
            </div>
          </div>

          <div className="flex flex-col items-center justify-center">
            <Link href="/profile/settings">
            <div className="flex flex-col w-[250px]">
              <RoundedGreyButton text="Discard" type="button" />
            </div>
            </Link>
          </div>

        </form>
      </div>
    </div>
    </CustomLayout>
    </>
  )
}

export default ChangePassword;