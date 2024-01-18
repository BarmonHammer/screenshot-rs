mod capture;
mod d3d;
mod display_info;
mod window_info;

use ndarray::prelude::*;
use ndarray::{Array3, ArrayBase, OwnedRepr, ShapeError};
use windows::core::{ComInterface, IInspectable};
use windows::Foundation::TypedEventHandler;
use windows::Graphics::Capture::{
    Direct3D11CaptureFrame, Direct3D11CaptureFramePool, GraphicsCaptureItem, GraphicsCaptureSession,
};
use windows::Graphics::DirectX::DirectXPixelFormat;
use windows::Win32::Foundation::HWND;
use windows::Win32::Graphics::Direct3D11::{
    ID3D11Device, ID3D11DeviceContext, ID3D11Resource, ID3D11Texture2D, D3D11_BIND_FLAG,
    D3D11_CPU_ACCESS_READ, D3D11_MAPPED_SUBRESOURCE, D3D11_MAP_READ, D3D11_RESOURCE_MISC_FLAG,
    D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING,
};
use windows::Win32::Graphics::Gdi::HMONITOR;
use windows::Win32::System::WinRT::{
    Graphics::Capture::IGraphicsCaptureItemInterop, RoInitialize, RO_INIT_MULTITHREADED,
};
use windows::Win32::UI::WindowsAndMessaging::GetWindowThreadProcessId;

use capture::enumerate_capturable_windows;
use std::sync::mpsc::{channel, Receiver};
use thiserror::Error;
use window_info::WindowInfo;

use windows::core::Error as WindowsError;

pub struct Recorder {
    receiver: Receiver<Direct3D11CaptureFrame>,
    frame_pool: Direct3D11CaptureFramePool,
    capture_session: GraphicsCaptureSession,
    d3d_context: ID3D11DeviceContext,
    d3d_device: ID3D11Device,
}

pub struct Window {
    recorded_item: GraphicsCaptureItem,
}

impl Window {
    pub fn new_from_name(window_name: String) -> Result<Self, SourceSelectionErr> {
        let window = get_window_from_query(&window_name)?;

        Ok(Window {
            recorded_item: create_capture_item_for_window(window.handle)?,
        })
    }
    pub fn create_record(&self) -> Result<Recorder, WindowsError> {
        unsafe {
            RoInitialize(RO_INIT_MULTITHREADED)?;
        }
        let item_size = self.recorded_item.Size()?;
        let d3d_device = d3d::create_d3d_device()?;
        let d3d_context = unsafe { d3d_device.GetImmediateContext()? };
        let device = d3d::create_direct3d_device(&d3d_device)?;
        let frame_pool = Direct3D11CaptureFramePool::CreateFreeThreaded(
            &device,
            DirectXPixelFormat::B8G8R8A8UIntNormalized,
            1,
            item_size,
        )?;
        let capture_session = frame_pool.CreateCaptureSession(&self.recorded_item)?;
        let (sender, receiver) = channel();

        //continuously get frames on seperate thread
        frame_pool.FrameArrived(
            &TypedEventHandler::<Direct3D11CaptureFramePool, IInspectable>::new({
                move |frame_pool: &Option<Direct3D11CaptureFramePool>,
                      _|
                      -> windows::core::Result<()> {
                    let frame_pool = frame_pool.as_ref().unwrap();
                    let frame = frame_pool.TryGetNextFrame()?;
                    sender.send(frame).unwrap();
                    Ok(())
                }
            }),
        )?;
        capture_session.SetIsBorderRequired(false)?;
        capture_session.StartCapture()?;

        //store initialized items to be used.
        Ok(Recorder {
            receiver,
            frame_pool,
            capture_session,
            d3d_context,
            d3d_device,
        })
    }
}

impl Recorder {
    fn get_texture(&self) -> Result<ID3D11Texture2D, TextureErr> {
        //get next frame from the capture thread
        let frame = self.receiver.recv()?;

        let source_texture: ID3D11Texture2D =
            d3d::get_d3d_interface_from_object(&frame.Surface()?)?;

        let mut desc = D3D11_TEXTURE2D_DESC::default();
        unsafe { source_texture.GetDesc(&mut desc) };
        desc.BindFlags = D3D11_BIND_FLAG(0);
        desc.MiscFlags = D3D11_RESOURCE_MISC_FLAG(0);
        desc.Usage = D3D11_USAGE_STAGING;
        desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;

        let copy_texture = {
            let mut texture = None;
            unsafe {
                self.d3d_device
                    .CreateTexture2D(&desc, None, Some(&mut texture))
            }?;
            texture.unwrap()
        };

        unsafe {
            self.d3d_context
                .CopyResource(Some(&copy_texture.cast()?), Some(&source_texture.cast()?));
        }

        Ok(copy_texture)
    }
    pub fn get_image(&self) -> Result<Array3<u8>, GetBitsErr> {
        let texture = self.get_texture()?;
        let mut desc = D3D11_TEXTURE2D_DESC::default();
        unsafe { texture.GetDesc(&mut desc as *mut _) };

        let resource: ID3D11Resource = texture.cast()?;

        let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
        unsafe {
            self.d3d_context.Map(
                Some(&resource.clone()),
                0,
                D3D11_MAP_READ,
                0,
                Some(&mut mapped),
            )
        }?;

        let slice: &[u8] = unsafe {
            std::slice::from_raw_parts(
                mapped.pData as *const _,
                (desc.Height * mapped.RowPitch) as usize,
            )
        };
        
        let vec: Vec<u8> = Vec::from(slice);

        unsafe { self.d3d_context.Unmap(Some(&resource), 0) };

        let ndarray: ArrayBase<OwnedRepr<u8>, Dim<[usize; 3]>> =
            ndarray::ArrayBase::from_shape_vec(
                (desc.Height as usize, desc.Width as usize, 4),
                vec,
            )?;
        Ok(ndarray)
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        self.capture_session
            .Close()
            .expect("Capture Session already closed?");
        self.frame_pool.Close().expect("Frame pool already closed?");
    }
}

fn create_capture_item_for_window(
    window_handle: HWND,
) -> windows::core::Result<GraphicsCaptureItem> {
    let interop = windows::core::factory::<GraphicsCaptureItem, IGraphicsCaptureItemInterop>()?;
    unsafe { interop.CreateForWindow(window_handle) }
}

fn create_capture_item_for_monitor(
    monitor_handle: HMONITOR,
) -> windows::core::Result<GraphicsCaptureItem> {
    let interop = windows::core::factory::<GraphicsCaptureItem, IGraphicsCaptureItemInterop>()?;
    unsafe { interop.CreateForMonitor(monitor_handle) }
}

#[derive(Error, Debug)]
pub enum SourceSelectionErr {
    #[error("monitor {} was selected, but max monitor id is {}", .selected_monitor, .max_id)]
    MonitorOutOfRange {
        selected_monitor: usize,
        max_id: usize,
    },
    #[error("no window with pid {} exists", .0)]
    NoWindowWithPid(u32),
    #[error(transparent)]
    WindowSelectionError(#[from] WindowSelectionErr),
    #[error(transparent)]
    WindowsError(#[from] WindowsError),
}

/*pub fn select_monitor(monitor_id: usize) -> Result<(), SourceSelectionErr> {
    let displays = enumerate_displays()?;
    if monitor_id >= displays.len() {
        return Err(SourceSelectionErr::MonitorOutOfRange {
            selected_monitor: monitor_id,
            max_id: displays.len(),
        });
    }
    let display = &displays[monitor_id];
    *RECORDED_ITEM.write() = Some(create_capture_item_for_monitor(display.handle)?);
    Ok(())
}

pub fn select_window_by_name(window_name: String) -> Result<(), SourceSelectionErr> {
    let window = get_window_from_query(&window_name)?;
    *RECORDED_ITEM.write() = Some(create_capture_item_for_window(window.handle)?);
    Ok(())
}

pub fn select_window_by_pid(pid: u32) -> Result<(), SourceSelectionErr> {
    let window = get_window_by_pid(pid).ok_or(SourceSelectionErr::NoWindowWithPid(pid))?;
    *RECORDED_ITEM.write() = Some(create_capture_item_for_window(window.handle)?);
    Ok(())
}*/

#[derive(Error, Debug)]
pub enum TextureErr {
    #[error(transparent)]
    WindowsError(#[from] WindowsError),
    #[error(transparent)]
    ChannelError(#[from] std::sync::mpsc::RecvError),
}

#[derive(Error, Debug)]
pub enum GetBitsErr {
    #[error(transparent)]
    WindowsError(#[from] WindowsError),
    #[error(transparent)]
    TextureErr(#[from] TextureErr),
    #[error(transparent)]
    ShapeErr(#[from] ShapeError),
}

#[derive(Debug, Error)]
pub enum ScreenshotErr {
    #[error(transparent)]
    TextureErr(#[from] TextureErr),
    #[error(transparent)]
    BitsErr(#[from] GetBitsErr),
}

#[derive(Debug, Error)]
pub enum WindowSelectionErr {
    #[error("no window found with parameter")]
    NoWindowFound,
    #[error("multiple windows found with pids: {:#?}", .0)]
    MultipleWindowsFound(Vec<u32>),
    #[error(transparent)]
    WindowsError(#[from] WindowsError),
}

fn get_window_from_query(query: &str) -> Result<WindowInfo, WindowSelectionErr> {
    let windows = find_windows_by_name(query);

    //if no windows match return error
    if windows.len() == 0 {
        return Err(WindowSelectionErr::NoWindowFound);
    }
    //if multiple windows match, return error with list of pids
    if windows.len() > 1 {
        let mut pid_vec: Vec<u32> = Vec::with_capacity(windows.len());
        for window in windows.iter() {
            let mut pid = 0;
            unsafe { GetWindowThreadProcessId(window.handle, Some(&mut pid)) };
            pid_vec.push(pid);
        }

        return Err(WindowSelectionErr::MultipleWindowsFound(pid_vec));
    };

    Ok(windows[0].clone())
}

fn find_windows_by_name(window_name: &str) -> Vec<WindowInfo> {
    let window_list = enumerate_capturable_windows();
    let mut windows: Vec<WindowInfo> = Vec::new();
    for window_info in window_list.into_iter() {
        let title = window_info.title.to_lowercase();
        if title.contains(&window_name.to_string().to_lowercase()) {
            windows.push(window_info.clone());
        }
    }
    windows
}

pub fn find_pids_by_name(window_name: &str) -> Vec<u32> {
    let window_list = enumerate_capturable_windows();
    let mut windows: Vec<u32> = Vec::new();
    for window_info in window_list.into_iter() {
        let title = window_info.title.to_lowercase();
        if title.contains(&window_name.to_string().to_lowercase()) {
            let mut current_pid = 0;
            unsafe { GetWindowThreadProcessId(window_info.handle, Some(&mut current_pid)) };
            windows.push(current_pid);
        }
    }
    windows
}

fn get_window_by_pid(pid: u32) -> Option<WindowInfo> {
    let window_list = enumerate_capturable_windows();
    for window_info in window_list.into_iter() {
        let mut current_pid = 0;
        unsafe { GetWindowThreadProcessId(window_info.handle, Some(&mut current_pid)) };
        if current_pid == pid {
            return Some(window_info);
        }
    }
    None
}
