"use client";
import React, { useEffect } from 'react' 
import CustomLayout from '@/components/CustomLayout';
import TopNavBar from '@/components/TopNavBar';
import {useState} from 'react';
import emailjs from '@emailjs/browser';
import { RootState } from '@/store/store';
import { useSelector } from 'react-redux';
import { set } from 'react-hook-form';


const FeedbackPage = () => {

const [name, setName] = useState('');
const [email, setEmail] = useState('');
const [message, setMessage] = useState('');
const [username, setUsername] = useState('');
const [successMessage, setSuccessMessage] = useState(false);

const user = useSelector((state: RootState) => state.user);

useEffect(() => {
    setUsername(user.USER_NAME);
}, [user]);

const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();

    //setUsername(user.USER_NAME);
    setSuccessMessage(true);
    
    console.log(name, email, message, username);

    

    const serviceId = 'service_j1pjtl4';
    const templateId = 'template_feedback';
    const publicKey = 'dtwyam3RG09Aud4Qq';

    const templateParams = {
        from_name: name,
        from_email: email,
        from_username: username,
        to_name: 'Chronicle Dev Team',
        message: message
    };

    emailjs.send(serviceId, templateId, templateParams, publicKey)
    .then((response) => {
        console.log('Successfully Sent Feedback Email!', response);
        
        
        setName('');
        setEmail('');
        setMessage('');

        setTimeout(() => {
            setSuccessMessage(false);
        }, 5000);

    })
    .catch((error) => {
        console.error('Failed to send feedback email', error);
    })
}

  return (
    <>
    <CustomLayout showNavbar>
        
            <div className='flex flex-col min-h-screen items-center bg-gradient-to-tl from-green-200 to-white'>
                <TopNavBar />
                
                <h1 className="text-3xl font-bold py-2 mt-2 text-green-500">Feedback</h1>
                
                <p className='text-lg font-semibold'>We would love to hear your feedback!</p>
                

                <div className='flex items-center justify-center'>
                    <form onSubmit={handleSubmit}>
                        <div className='flex flex-col items-center'>
                        <input className='border-2 border-gray-300 p-2 m-2 rounded-lg'
                            type="text" 
                            placeholder="Name" 
                            value={name} 
                            onChange={(e) => setName(e.target.value)} 
                            />
                        <input className='border-2 border-gray-300 p-2 m-2 rounded-lg '
                            type="email"
                            placeholder="Email"
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            />
                        </div>


                        <div className='flex flex-col items-center'>
                        <label className='font-semibold' htmlFor="message">Message</label>
                        <textarea className='border-2 border-gray-300 p-2 m-2 rounded-lg'
                            id="message"
                            cols={30}
                            rows={5}
                            value={message}
                            onChange={(e) => setMessage(e.target.value)}
                            placeholder="Enter your message"
                        >                           
                        </textarea>
                        </div>
                        
                        <br/>

                        <div className='flex flex-col items-center'>
                            <button className="w-1/2 flex justify-center py-2 px-4 border border-transparent rounded-full shadow-sm text-md font-medium text-white bg-green-600 hover:bg-green-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500 font-sans" type="submit">Submit</button>
                        </div>


                        </form>
                </div>

                <div className='flex flex-col items-center m-6'>
                    {successMessage && <p className='text-green-500 rounded-lg p-2 bg-white border border-green-500'>Feedback Sent!</p>}
                    </div>

            </div>
    </CustomLayout>
    </>
  )
}

export default FeedbackPage
