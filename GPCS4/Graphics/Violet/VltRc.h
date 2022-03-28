#pragma once

#include <atomic>
#include <cstdint>

namespace sce::vlt
{
	/**
	 * \brief Reference-counted object
	 */
	class RcObject
	{

	public:
		/**
		 * \brief We need a virtual destructor at the top
		 * of the inherience tree, to let delete father
		 * pointer correctly call child's destructor
		 */
		virtual ~RcObject()
		{
		}
		/**
		 * \brief Increments reference count
		 * \returns New reference count
		 */
		uint32_t incRef()
		{
			return ++m_refCount;
		}

		/**
		 * \brief Decrements reference count
		 * \returns New reference count
		 */
		uint32_t decRef()
		{
			return --m_refCount;
		}

	private:
		std::atomic<uint32_t> m_refCount = { 0u };
	};



	/**
	 * \brief Pointer for reference-counted objects
	 * 
	 * This only requires the given type to implement \c incRef
	 * and \c decRef methods that adjust the reference count.
	 * \tparam T Object type
	 */
	template <typename T>
	class Rc
	{
		template <typename Tx>
		friend class Rc;

	public:
		Rc()
		{
		}
		Rc(std::nullptr_t)
		{
		}

		Rc(T* object) :
			m_object(object)
		{
			this->incRef();
		}

		Rc(const Rc& other) :
			m_object(other.m_object)
		{
			this->incRef();
		}

		template <typename Tx>
		Rc(const Rc<Tx>& other) :
			m_object(other.m_object)
		{
			this->incRef();
		}

		Rc(Rc&& other) :
			m_object(other.m_object)
		{
			other.m_object = nullptr;
		}

		template <typename Tx>
		Rc(Rc<Tx>&& other) :
			m_object(other.m_object)
		{
			other.m_object = nullptr;
		}

		Rc& operator=(std::nullptr_t)
		{
			this->decRef();
			m_object = nullptr;
			return *this;
		}

		Rc& operator=(const Rc& other)
		{
			other.incRef();
			this->decRef();
			m_object = other.m_object;
			return *this;
		}

		template <typename Tx>
		Rc& operator=(const Rc<Tx>& other)
		{
			other.incRef();
			this->decRef();
			m_object = other.m_object;
			return *this;
		}

		Rc& operator=(Rc&& other)
		{
			this->decRef();
			this->m_object = other.m_object;
			other.m_object = nullptr;
			return *this;
		}

		template <typename Tx>
		Rc& operator=(Rc<Tx>&& other)
		{
			this->decRef();
			this->m_object = other.m_object;
			other.m_object = nullptr;
			return *this;
		}

		~Rc()
		{
			this->decRef();
		}

		T& operator*() const
		{
			return *m_object;
		}
		T* operator->() const
		{
			return m_object;
		}
		T* ptr() const
		{
			return m_object;
		}

		bool operator==(const Rc& other) const
		{
			return m_object == other.m_object;
		}
		bool operator!=(const Rc& other) const
		{
			return m_object != other.m_object;
		}

		bool operator==(std::nullptr_t) const
		{
			return m_object == nullptr;
		}
		bool operator!=(std::nullptr_t) const
		{
			return m_object != nullptr;
		}
		operator bool() const
		{
			return m_object != nullptr;
		}

	private:
		T* m_object = nullptr;

		void incRef() const
		{
			if (m_object != nullptr)
				m_object->incRef();
		}

		void decRef() const
		{
			if (m_object != nullptr)
			{
				if (m_object->decRef() == 0)
					delete m_object;
			}
		}
	};

}  // namespace util
